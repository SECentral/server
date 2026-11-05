require "digest"
require "ipaddr"
require "socket"
require "uri"

# A Rack boundary deliberately ahead of Rails request/parameter logging.
class McpEndpoint
  MAX_RESPONSE_BYTES = 128 * 1024
  LOOPBACK_HOSTS = %w[localhost 127.0.0.1 [::1]].freeze

  class Admission
    def initialize(clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
      @clock = clock
      @mutex = Mutex.new
      @tokens = 5.0
      @last = @clock.call
      @active = 0
    end

    def acquire
      @mutex.synchronize do
        now = @clock.call
        @tokens = [5.0, @tokens + (now - @last) * 0.5].min
        @last = now
        return 1 if @active >= 2
        return ((1 - @tokens) / 0.5).ceil if @tokens < 1

        @tokens -= 1
        @active += 1
        nil
      end
    end

    def release
      @mutex.synchronize { @active -= 1 }
    end
  end

  def initialize(app)
    @app = app
    @admission = Admission.new
  end

  def call(env)
    path = env["PATH_INFO"].to_s
    return @app.call(env) unless path == "/mcp" || path.start_with?("/mcp/")

    response = dispatch(env, path)
    Rails.logger.info("mcp integration=investigation status=#{response[0]}")
    [response[0], response[1].merge("cache-control" => "no-store"), response[2]]
  end

  private

  attr_reader :admission

  def dispatch(env, path)
    configured = ENV.fetch("SECENTRAL_MCP_AUTH_TOKEN", "")
    return empty(404) if configured.strip.empty? || path != "/mcp"

    supplied = env["HTTP_AUTHORIZATION"].to_s[/\ABearer +([^\s]+)\z/i, 1]
    unless supplied && secure_equal?(configured, supplied)
      return [401, { "www-authenticate" => 'Bearer realm="mcp-investigation"' }, []]
    end
    return failure(403, "invalid_host_or_origin") unless valid_exposure?(env)
    return [405, { "allow" => "POST" }, []] unless env["REQUEST_METHOD"] == "POST"
    if env.key?("HTTP_MCP_SESSION_ID") || env.key?("HTTP_LAST_EVENT_ID")
      return failure(400, "unsupported_session_operation")
    end
    version = env["HTTP_MCP_PROTOCOL_VERSION"]
    if MCP::Configuration.handshake_protocol_version?(version) && version != "2025-11-25"
      return failure(400, "unsupported_protocol_version")
    end

    retry_after = admission.acquire
    return failure(429, "rate_limited", "retry-after" => retry_after.to_s) if retry_after

    begin
      status, headers, body = Rails.application.reloader.wrap do
        McpInvestigation::Tools.transport.call(env)
      end
      bytes = +""
      body.each do |part|
        return failure(503, "scope_exceeds_limit") if bytes.bytesize + part.bytesize > MAX_RESPONSE_BYTES

        bytes << part
      end
      [status, headers, [bytes]]
    ensure
      body.close if body.respond_to?(:close)
      admission.release
    end
  rescue StandardError
    # Do not log SDK errors/requests: these may contain credentials or evidence.
    failure(500, "internal_error")
  end

  def valid_exposure?(env)
    authority = env["HTTP_HOST"].to_s.downcase
    return false unless authority.match?(/\A(?:[a-z0-9.-]+|\[::1\])(?::[0-9]{1,5})?\z/)

    accepted = ENV.fetch("SECENTRAL_MCP_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]").split(",").map { |value| value.strip.downcase }
    return false unless accepted.include?(authority)

    peer = IPAddr.new(env.fetch("REMOTE_ADDR", ""))
    # Puma may derive rack.url_scheme from untrusted forwarding headers.
    direct_https = %w[on https].include?(env["HTTPS"])
    trusted = ENV.fetch("SECENTRAL_MCP_TRUSTED_PROXIES", "").split(",").any? { |proxy| trusted_proxy?(proxy.strip, peer) }
    https = direct_https || (trusted && env["HTTP_X_FORWARDED_PROTO"] == "https")
    public_origin = ENV["SECENTRAL_MCP_PUBLIC_ORIGIN"].to_s
    if public_origin.empty?
      return false unless peer.loopback? && LOOPBACK_HOSTS.include?(authority.sub(/:\d+\z/, ""))

      expected_origin = "#{https ? 'https' : 'http'}://#{authority}"
    else
      origin = URI.parse(public_origin)
      return false unless https && origin.scheme == "https" && origin.host && origin.userinfo.nil? &&
        origin.path.empty? && origin.query.nil? && origin.fragment.nil? && origin.to_s == public_origin
      request_origin = URI.parse("https://#{authority}")
      return false unless origin.host.downcase == request_origin.host&.downcase && origin.port == request_origin.port

      expected_origin = public_origin
    end
    !env.key?("HTTP_ORIGIN") || env["HTTP_ORIGIN"] == expected_origin
  rescue IPAddr::Error, URI::InvalidURIError
    false
  end

  def trusted_proxy?(proxy, peer)
    IPAddr.new(proxy).include?(peer)
  rescue IPAddr::InvalidAddressError
    return false unless proxy.match?(/\A[a-zA-Z0-9][a-zA-Z0-9.-]*\z/)

    # Resolve each request so recreated proxy containers do not retain trust.
    begin
      Addrinfo.getaddrinfo(proxy, nil, :UNSPEC, :STREAM, timeout: 0.25).any? { |address| IPAddr.new(address.ip_address) == peer }
    rescue SocketError, IO::TimeoutError
      false
    end
  end

  def secure_equal?(expected, actual)
    Rack::Utils.secure_compare(Digest::SHA256.digest(expected), Digest::SHA256.digest(actual))
  end

  def empty(status)
    [status, {}, []]
  end

  def failure(status, code, headers = {})
    [status, headers.merge("content-type" => "application/json"), [JSON.generate(error: { code: code })]]
  end
end
