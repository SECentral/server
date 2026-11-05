require "rails_helper"

RSpec.describe "MCP admission wiring", type: :request do
  it "admits authenticated requests and rejects the next request when the real gate is exhausted" do
    keys = %w[SECENTRAL_MCP_AUTH_TOKEN SECENTRAL_MCP_ALLOWED_HOSTS SECENTRAL_MCP_PUBLIC_ORIGIN SECENTRAL_MCP_TRUSTED_PROXIES]
    saved = keys.to_h { |key| [key, ENV[key]] }
    keys.each { |key| ENV.delete(key) }
    ENV["SECENTRAL_MCP_AUTH_TOKEN"] = "admission-test-token"

    gate = McpEndpoint::Admission.new(clock: -> { 0.0 })
    allow(McpEndpoint::Admission).to receive(:new).and_return(gate)
    client = Rack::MockRequest.new(McpEndpoint.new(->(_env) { [404, {}, []] }))
    headers = { "HTTP_HOST" => "127.0.0.1", "REMOTE_ADDR" => "127.0.0.1",
      "HTTP_AUTHORIZATION" => "Bearer admission-test-token", "CONTENT_TYPE" => "application/json",
      "HTTP_ACCEPT" => "application/json, text/event-stream", "HTTP_MCP_PROTOCOL_VERSION" => "2025-11-25",
      input: { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }.to_json }

    expect(client.post("/mcp", headers.merge("HTTP_AUTHORIZATION" => "Bearer wrong")).status).to eq(401)
    5.times do
      response = client.post("/mcp", headers)
      expect(response.status).to eq(200)
      expect(JSON.parse(response.body).dig("result", "tools")).to be_an(Array)
    end
    rejected = client.post("/mcp", headers)
    expect(rejected.status).to eq(429)
    expect(rejected["retry-after"]).to eq("2")
    expect(JSON.parse(rejected.body).dig("error", "code")).to eq("rate_limited")
  ensure
    saved&.each { |key, value| ENV[key] = value }
  end
end
