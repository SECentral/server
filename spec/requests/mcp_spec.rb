require "rails_helper"
require "stringio"

RSpec.describe "MCP investigation endpoint", type: :request do
  include ActiveJob::TestHelper

  SETTINGS = %w[SECENTRAL_MCP_AUTH_TOKEN SECENTRAL_MCP_ALLOWED_HOSTS SECENTRAL_MCP_PUBLIC_ORIGIN SECENTRAL_MCP_TRUSTED_PROXIES SECENTRAL_METRICS_TOKEN].freeze
  let(:authorization) { "Bearer investigation-test-token" }
  let(:revision) { "2026-07-28" }

  around do |example|
    saved = SETTINGS.to_h { |key| [key, ENV[key]] }
    SETTINGS.each { |key| ENV.delete(key) }
    ENV["SECENTRAL_MCP_AUTH_TOKEN"] = "investigation-test-token"
    ENV["SECENTRAL_METRICS_TOKEN"] = "distinct-metrics-token"
    clean_database
    example.run
  ensure
    saved.each { |key, value| ENV[key] = value }
    clean_database
    clear_enqueued_jobs
  end

  before do
    host! "127.0.0.1"
    allow_any_instance_of(McpEndpoint::Admission).to receive(:acquire).and_return(nil)
    allow_any_instance_of(McpEndpoint::Admission).to receive(:release)
  end

  def clean_database
    raise "MCP specs require an isolated test database" unless Rails.env.test?

    connection = ActiveRecord::Base.connection
    tables = connection.tables - %w[schema_migrations ar_internal_metadata]
    connection.execute("TRUNCATE #{tables.map { |table| connection.quote_table_name(table) }.join(', ')} CASCADE")
  end

  def rpc(method, arguments = {}, headers: {}, version: revision, raw: nil)
    extra = version == "2026-07-28" ? { _meta: {
      "io.modelcontextprotocol/protocolVersion" => version, "io.modelcontextprotocol/clientCapabilities" => {}
    } } : {}
    body = { jsonrpc: "2.0", id: 1, method: method, params: arguments.merge(extra) }
    standard = { "Authorization" => authorization, "Content-Type" => "application/json", "Accept" => "application/json, text/event-stream" }
    standard["MCP-Protocol-Version"] = version if version
    if version == "2026-07-28"
      standard["Mcp-Method"] = method
      standard["Mcp-Name"] = arguments[:name] if arguments[:name]
    end
    post "/mcp", params: raw || JSON.generate(body), headers: standard.merge(headers)
    JSON.parse(response.body) unless response.body.empty?
  end

  def call_tool(name, arguments = {})
    rpc("tools/call", { name: name, arguments: arguments })
  end

  def organization
    @organization ||= Organization.create!(name: "mcp-spec")
  end

  def issue(source: "httpd_t")
    organization.issues.create!(fingerprint_version: 3, fingerprint_digest: SecureRandom.hex,
      source_type: source, target_type: "user_home_t", target_class: "file", permissions: ["read"],
      first_seen_at: Time.current, last_seen_at: Time.current)
  end

  def commit_concurrently(&block)
    Thread.new { ActiveRecord::Base.connection_pool.with_connection(&block) }.value
  end

  def result_for(name, arguments = {})
    result = call_tool(name, arguments).fetch("result")
    expect(response).to have_http_status(:ok)
    expect(result["isError"]).to be(false), result.inspect
    structured = result.fetch("structuredContent")
    expect(JSONSchemer.schema(McpInvestigation::Contracts.output(name)).valid?(structured)).to be(true)
    structured
  end

  [nil, "", " \t\n"].each do |value|
    it "is disabled for #{value.inspect} before SDK dispatch" do
      ENV["SECENTRAL_MCP_AUTH_TOKEN"] = value
      expect(McpInvestigation::Tools).not_to receive(:transport)
      rpc("server/discover")
      expect(response).to have_http_status(:not_found)
      expect(response.headers["Cache-Control"]).to eq("no-store")
    end
  end

  %w[get post delete put options head].each do |method|
    it "authenticates #{method} before SDK dispatch" do
      expect(McpInvestigation::Tools).not_to receive(:transport)
      public_send(method, "/mcp")
      expect(response).to have_http_status(:unauthorized)
      expect(response.headers["WWW-Authenticate"]).to eq('Bearer realm="mcp-investigation"')
      expect(response.headers["Cache-Control"]).to eq("no-store")
    end
  end

  ["Bearer wrong", "Bearer test-ingestion-key", "Bearer distinct-metrics-token", "Basic investigation-test-token", "Bearer investigation-test-token extra"].each do |value|
    it "rejects unrelated credentials #{value.inspect}" do
      rpc("server/discover", headers: { "Authorization" => value })
      expect(response).to have_http_status(:unauthorized)
    end
  end

  it "does not authorize browser sessions" do
    sign_in_operator
    rpc("server/discover", headers: { "Authorization" => nil })
    expect(response).to have_http_status(:unauthorized)
  end

  ["/mcp/", "/mcp/anything"].each do |path|
    it "reserves #{path} instead of serving the SPA" do
      get path, headers: { "Authorization" => authorization }
      expect(response).to have_http_status(:not_found)
      expect(response.body).not_to include('<div id="root">')
    end
  end

  it "validates Host even when Origin is omitted or apparently valid" do
    rpc("server/discover", headers: { "Host" => "attacker.invalid", "Origin" => "http://127.0.0.1" })
    expect(response).to have_http_status(:forbidden)
    rpc("server/discover", headers: { "Host" => "attacker.invalid" })
    expect(response).to have_http_status(:forbidden)
  end

  it "independently validates Origin and ignores forged forwarded host headers" do
    rpc("server/discover", headers: { "Origin" => "https://attacker.invalid", "X-Forwarded-Host" => "127.0.0.1" })
    expect(response).to have_http_status(:forbidden)
    rpc("server/discover", headers: { "Origin" => "http://127.0.0.1", "X-Forwarded-Host" => "attacker.invalid" })
    expect(response).to have_http_status(:ok)
  end

  it "keeps remote access closed without explicit public configuration" do
    rpc("server/discover", headers: { "REMOTE_ADDR" => "192.0.2.5", "X-Forwarded-Proto" => "https" })
    expect(response).to have_http_status(:forbidden)
  end

  it "requires a trusted proxy for forwarded HTTPS and a separately accepted authority" do
    ENV["SECENTRAL_MCP_PUBLIC_ORIGIN"] = "https://investigation.example"
    ENV["SECENTRAL_MCP_ALLOWED_HOSTS"] = "investigation.example"
    extra = { "Host" => "investigation.example", "REMOTE_ADDR" => "192.0.2.5", "X-Forwarded-Proto" => "https" }
    rpc("server/discover", headers: extra)
    expect(response).to have_http_status(:forbidden)
    endpoint = McpEndpoint.new(nil)
    transport = { "HTTP_HOST" => "investigation.example", "REMOTE_ADDR" => "192.0.2.5",
      "rack.url_scheme" => "https", "HTTP_X_FORWARDED_PROTO" => "https",
      "PATH_INFO" => "/mcp", "REQUEST_METHOD" => "GET", "HTTP_AUTHORIZATION" => authorization }
    expect(endpoint.call(transport).first).to eq(403)
    expect(endpoint.call(transport.merge("HTTPS" => "https")).first).to eq(405)
    ENV["SECENTRAL_MCP_TRUSTED_PROXIES"] = "192.0.2.5/32"
    rpc("server/discover", headers: extra)
    expect(response).to have_http_status(:ok)
    rpc("server/discover", headers: extra.merge("Origin" => "https://attacker.invalid"))
    expect(response).to have_http_status(:forbidden)
  end

  it "trusts only the current DNS addresses of the configured proxy" do
    ENV["SECENTRAL_MCP_PUBLIC_ORIGIN"] = "https://investigation.example"
    ENV["SECENTRAL_MCP_ALLOWED_HOSTS"] = "investigation.example"
    ENV["SECENTRAL_MCP_TRUSTED_PROXIES"] = "caddy"
    extra = { "Host" => "investigation.example", "REMOTE_ADDR" => "192.0.2.5", "X-Forwarded-Proto" => "https" }
    address = "192.0.2.5"
    allow(Addrinfo).to receive(:getaddrinfo).with("caddy", nil, :UNSPEC, :STREAM, timeout: 0.25) do
      raise address if address.is_a?(Class)

      [Addrinfo.ip(address)]
    end
    rpc("server/discover", headers: extra)
    expect(response).to have_http_status(:ok)
    rpc("server/discover", headers: extra.merge("X-Forwarded-Proto" => "http"))
    expect(response).to have_http_status(:forbidden)
    rpc("server/discover", headers: extra.merge("Origin" => "https://attacker.invalid"))
    expect(response).to have_http_status(:forbidden)
    address = "192.0.2.6"
    rpc("server/discover", headers: extra)
    expect(response).to have_http_status(:forbidden)
    rpc("server/discover", headers: extra.merge("REMOTE_ADDR" => "192.0.2.6"))
    expect(response).to have_http_status(:ok)
    [SocketError, IO::TimeoutError].each do |error|
      address = error
      rpc("server/discover", headers: extra)
      expect(response).to have_http_status(:forbidden)
    end
  end

  %w[2025-11-25 2026-07-28].each do |version|
    it "discovers and calls only safe tools with #{version}" do
      organization
      if version == "2025-11-25"
        initialized = rpc("initialize", { protocolVersion: version, capabilities: {}, clientInfo: { name: "unverified", version: "1" } }, version: nil)
        expect(initialized.dig("result", "protocolVersion")).to eq(version)
        expect(initialized.dig("result", "capabilities")).to eq("tools" => {})
      else
        discovered = rpc("server/discover", version: version)
        expect(discovered.dig("result", "capabilities")).to eq("tools" => {})
      end
      tools = rpc("tools/list", version: version).dig("result", "tools")
      expect(tools.map { |tool| tool.fetch("name") }).to match_array(McpInvestigation::Tools::DESCRIPTIONS.keys)
      expect(tools).to all(include("annotations" => include("readOnlyHint" => true, "destructiveHint" => false)))
      expect(response.headers).not_to have_key("mcp-session-id")
      expect(rpc("tools/call", { name: "get_overview", arguments: {} }, version: version).dig("result", "structuredContent", "data", "host_count")).to eq(0)
    end
  end

  it "rejects unsupported session and streaming operations" do
    %w[GET DELETE OPTIONS].each do |method|
      public_send(method.downcase, "/mcp", headers: { "Authorization" => authorization })
      expect(response).to have_http_status(:method_not_allowed)
    end
    %w[Mcp-Session-Id Last-Event-ID].each do |header|
      rpc("tools/list", headers: { header => "untrusted" })
      expect(response).to have_http_status(:bad_request)
      expect(response.parsed_body.dig("error", "code")).to eq("unsupported_session_operation")
    end
    expect(rpc("subscriptions/listen").dig("error", "code")).to eq(-32601)
  end

  it "offers only the supported legacy revision, even when an older version is requested" do
    body = rpc("initialize", { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "test", version: "1" } }, version: nil)
    expect(body.dig("result", "protocolVersion")).to eq("2025-11-25")
    rpc("tools/list", version: "2025-03-26")
    expect(response).to have_http_status(:bad_request)
  end

  it "rejects rate admission before protocol dispatch and supplies retry guidance" do
    allow_any_instance_of(McpEndpoint::Admission).to receive(:acquire).and_return(2)
    expect(McpInvestigation::Tools).not_to receive(:transport)
    rpc("server/discover")
    expect(response).to have_http_status(:too_many_requests)
    expect(response.headers["Retry-After"]).to eq("2")
    expect(response.parsed_body.dig("error", "code")).to eq("rate_limited")
  end

  it "rejects malformed requests and bounds bodies before protocol dispatch" do
    rpc("tools/list", raw: "{")
    expect(response).to have_http_status(:bad_request)
    rpc("tools/list", raw: "x" * 16_385)
    expect(response).to have_http_status(:content_too_large)
    rpc("tools/list", headers: { "Accept" => "text/plain" })
    expect(response).to have_http_status(:not_acceptable)
    rpc("tools/list", headers: { "Content-Type" => "text/plain" })
    expect(response).to have_http_status(:unsupported_media_type)
    rpc("tools/list", version: "2099-01-01")
    expect(response).to have_http_status(:bad_request)
    expect(response.parsed_body.dig("error", "code")).to eq(-32022)
    expect(response.parsed_body.dig("error", "data", "supported")).to include("2026-07-28")
  end

  it "does not register analysis, configuration, raw evidence or mutation tools prematurely" do
    %w[get_issue_analysis get_host_configuration get_issue_occurrence get_issue_resolutions update_status clear_resolution_intent].each do |name|
      result = call_tool(name)
      expect(result["error"] || result.dig("result", "isError")).to be_truthy
    end
  end

  it "strictly validates arguments before a database read" do
    expect(McpInvestigation::Reader).not_to receive(:new)
    expect(call_tool("list_issues", { limit: 51 }).dig("result", "isError")).to be(true)
    expect(call_tool("get_issue", { issue_id: 1 }).dig("result", "isError")).to be(true)
    expect(call_tool("get_host", { host_id: "1", include_raw: true }).dig("result", "isError")).to be(true)
  end

  it "fails clearly for missing or multiple organizations rather than creating one" do
    expect(call_tool("get_overview").dig("result", "structuredContent", "error", "code")).to eq("organization_invariant_missing")
    organization
    Organization.create!(name: "second")
    expect(call_tool("get_overview").dig("result", "structuredContent", "error", "code")).to eq("organization_invariant_missing")
    expect(Organization.count).to eq(2)
  end

  it "uses recent-first bounded continuation and excludes newly inserted higher IDs" do
    first = issue(source: "first_t")
    second = issue(source: "second_t")
    third = issue(source: "third_t")
    page = result_for("list_issues", { limit: 1 })
    expect(page.dig("data", "issues").pluck("id")).to eq([third.id.to_s])
    newer = issue(source: "newer_t")
    next_page = result_for("list_issues", { limit: 2, cursor: page.dig("retrieval", "next_cursor") })
    expect(next_page.dig("data", "issues").pluck("id")).to eq([second.id.to_s, first.id.to_s])
    expect(next_page.dig("data", "issues").pluck("id")).not_to include(newer.id.to_s)
    expect(next_page.dig("retrieval", "change_detection")).to eq("unknown")
    expect(next_page.dig("retrieval", "has_more")).to be(false)
  end

  it "rejects tampered and cross-tool/filter continuations" do
    issue(source: "first_t")
    issue(source: "second_t")
    cursor = result_for("list_issues", { limit: 1 }).dig("retrieval", "next_cursor")
    expect(call_tool("list_hosts", { cursor: cursor }).dig("result", "structuredContent", "error", "code")).to eq("invalid_arguments")
    expect(call_tool("list_issues", { cursor: cursor + "x" }).dig("result", "structuredContent", "error", "code")).to eq("invalid_arguments")
    expect(call_tool("list_issues", { cursor: cursor, status: "all" }).dig("result", "structuredContent", "error", "code")).to eq("invalid_arguments")
  end

  %w[deletion filter_change].each do |change|
    it "keeps a consistent page when #{change} commits after ID selection" do
      older = issue(source: "older_t")
      selected = issue(source: "selected_t")
      changed = false
      allow_any_instance_of(McpInvestigation::Reader).to receive(:project).and_wrap_original do |original, *arguments|
        unless changed
          changed = true
          commit_concurrently do
            scope = Issue.where(id: selected.id)
            change == "deletion" ? scope.delete_all : scope.update_all(status: "resolved")
          end
        end
        original.call(*arguments)
      end

      page = result_for("list_issues", { limit: 1 })
      expect(page.dig("data", "issues").pluck("id")).to eq([selected.id.to_s])
      expect(page.dig("data", "issues", 0, "status")).to eq("open")
      expect(page["reasons"]).to include("no_cross_call_snapshot")
      expect(page.dig("retrieval", "has_more")).to be(true)
      expect(Issue.where(id: selected.id).pick(:status)).to eq(change == "deletion" ? nil : "resolved")

      following = result_for("list_issues", { limit: 1, cursor: page.dig("retrieval", "next_cursor") })
      expect(following.dig("data", "issues").pluck("id")).to eq([older.id.to_s])
      expect(following.dig("retrieval", "has_more")).to be(false)
      fresh = result_for("list_issues", { limit: 2, status: "all" }).dig("data", "issues")
      if change == "deletion"
        expect(fresh.pluck("id")).to eq([older.id.to_s])
      else
        expect(fresh.first).to include("id" => selected.id.to_s, "status" => "resolved")
      end
    end
  end

  it "returns only domain-active signatures, including never-observed signatures" do
    item = issue
    current, retired, unobserved, mixed = 4.times.map do |index|
      item.signatures.create!(fingerprint_version: 3, fingerprint_digest: "signature-#{index}",
        permissions: ["read"], first_seen_at: Time.current, last_seen_at: Time.current)
    end
    host = organization.hosts.create!(external_id: "signature-host")
    installation = organization.agent_installations.create!(name: "signature-agent", bound_host: host)
    at = Time.current
    event = organization.raw_events.create!(host: host, agent_installation: installation, audit_timestamp: at,
      audit_sequence: 1, boot_id: "signature-boot", completion_reason: "eoe", evidence_digest: "digest",
      agent_received_at: at, server_received_at: at, schema_version: 4)
    [[current, nil], [retired, at], [mixed, at], [mixed, nil]].each_with_index do |(signature, superseded), index|
      denial = event.normalized_denials.create!(ordinal: index, normalization_version: 1, status: "ok")
      Occurrence.create!(organization: organization, issue: item, issue_signature: signature, host: host,
        raw_event: event, normalized_denial: denial, occurred_at: at, superseded_at: superseded)
    end

    first = result_for("get_issue", { issue_id: item.id.to_s, limit: 2 })
    expect(first.dig("data", "active_occurrence_count")).to eq(2)
    expect(first.dig("data", "signatures").pluck("id")).to eq([mixed.id.to_s, unobserved.id.to_s])
    second = result_for("get_issue", { issue_id: item.id.to_s, limit: 2, cursor: first.dig("retrieval", "next_cursor") })
    expect(second.dig("data", "signatures").pluck("id")).to eq([current.id.to_s])
    expect(second.dig("retrieval", "has_more")).to be(false)
  end

  it "projects safe issue, intent, occurrence and host fields without transitive work" do
    item = issue
    host = organization.hosts.create!(external_id: "private-external-id", hostname: "allowed-hostname")
    installation = organization.agent_installations.create!(name: "agent", bound_host: host)
    at = Time.current
    event = organization.raw_events.create!(host: host, agent_installation: installation, audit_timestamp: at,
      audit_sequence: 1, boot_id: "private-boot", completion_reason: "eoe", evidence_digest: "digest",
      agent_received_at: at, server_received_at: at, schema_version: 4)
    denial = event.normalized_denials.create!(ordinal: 0, normalization_version: 1, status: "ok", command: "PRIVATE-COMMAND",
      executable: "/private/executable", details: { secret: "PRIVATE-DETAILS" })
    Occurrence.create!(organization: organization, issue: item, host: host, raw_event: event, normalized_denial: denial, occurred_at: at)
    ResolutionIntent.create!(issue: item, candidate_id: "candidate", candidate_kind: "restore_configured_label", status: "selected",
      selected_at: at, selected_intent: "PRIVATE-INTENT", operator: "PRIVATE-OPERATOR", evidence_version: "version",
      semantic_plan_basis: { private: "PRIVATE-BASIS" }, plan_semantics_version: 1, plan_snapshot: { command: "PRIVATE-PLAN" })
    ResolutionIntentChange.create!(issue: item, action: "selected", operator: "PRIVATE-OPERATOR", details: { private: "PRIVATE-HISTORY" })
    [IssueIntelligence, PolicyEvaluation, PolicyPermissiveDomains, IssueDiagnosis, ResolutionCandidates, ResolutionWorkflow].each do |service|
      expect(service).not_to receive(:new)
      expect(service).not_to receive(:call) if service.respond_to?(:call)
    end
    statements = []
    subscription = ActiveSupport::Notifications.subscribe("sql.active_record") { |*, payload| statements << payload[:sql] }
    results = [result_for("get_overview"), result_for("get_issue", { issue_id: item.id.to_s }),
      result_for("list_issue_occurrences", { issue_id: item.id.to_s }), result_for("get_issue_resolution_intent", { issue_id: item.id.to_s }),
      result_for("list_hosts"), result_for("get_host", { host_id: host.id.to_s })]
    expect(results.to_json).not_to match(/PRIVATE-|private-external-id|private-boot/)
    expect(statements.grep(/\b(INSERT|UPDATE|DELETE|MERGE)\b/i)).to be_empty
    expect(enqueued_jobs).to be_empty
    expect(results[3].dig("data", "intents").size).to eq(1)
    expect(results[3].dig("data", "history").size).to eq(1)
  ensure
    ActiveSupport::Notifications.unsubscribe(subscription) if subscription
  end

  it "returns a partial omission before loading oversized text, without silently truncating it" do
    host = organization.hosts.create!(external_id: "host", hostname: "secret-" * 1000)
    structured = result_for("get_host", { host_id: host.id.to_s })
    expect(structured["coverage"]).to eq("partial")
    expect(structured.dig("data", "host", "hostname")).to be_nil
    expect(structured["omitted_fields"]).to include("record_id" => host.id.to_s, "field" => "hostname", "reason" => "record_exceeds_budget")
    expect(response.body).not_to include("secret-")
  end

  [["x" * 513], ["é" * 513], Array.new(513, "x"), Array.new(16, "x" * 300)].each do |permissions|
    it "omits permissions outside the contract or byte budget (#{permissions.size} entries, #{permissions.first.size} characters)" do
      item = issue
      item.update!(permissions: permissions)
      signature = item.signatures.create!(fingerprint_version: 3, fingerprint_digest: "oversized-permissions",
        permissions: permissions, first_seen_at: Time.current, last_seen_at: Time.current)

      listed = result_for("list_issues")
      detail = result_for("get_issue", { issue_id: item.id.to_s })
      [listed, detail].each do |result|
        expect(result["coverage"]).to eq("partial")
        expect(result["omitted_fields"]).to include("record_id" => item.id.to_s, "field" => "permissions", "reason" => "record_exceeds_budget")
      end
      expect(listed.dig("data", "issues", 0, "permissions")).to be_nil
      expect(detail.dig("data", "issue", "permissions")).to be_nil
      expect(detail.dig("data", "signatures", 0, "permissions")).to be_nil
      expect(detail["omitted_fields"]).to include("record_id" => signature.id.to_s, "field" => "permissions", "reason" => "record_exceeds_budget")
    end
  end

  [["x" * 512], ["é" * 512], Array.new(512, "x"), []].each do |permissions|
    it "preserves permissions at the contract boundaries (#{permissions.size} entries, #{permissions.first&.size} characters)" do
      item = issue
      item.update!(permissions: permissions)
      item.signatures.create!(fingerprint_version: 3, fingerprint_digest: "bounded-permissions",
        permissions: permissions, first_seen_at: Time.current, last_seen_at: Time.current)

      listed = result_for("list_issues")
      detail = result_for("get_issue", { issue_id: item.id.to_s })
      [listed, detail].each do |result|
        expect(result["coverage"]).to eq("complete")
        expect(result["omitted_fields"]).to be_empty
      end
      expect(listed.dig("data", "issues", 0, "permissions")).to eq(permissions)
      expect(detail.dig("data", "issue", "permissions")).to eq(permissions)
      expect(detail.dig("data", "signatures", 0, "permissions")).to eq(permissions)
    end
  end

  it "does not charge omitted permission arrays against the stored-field page budget" do
    50.times do |index|
      issue(source: "omitted_#{index}_t").update!(permissions: Array.new(513, "x"))
    end
    result = result_for("list_issues", { limit: 50 })
    expect(result.dig("data", "issues").size).to eq(50)
    expect(result.dig("data", "issues").pluck("permissions")).to eq([nil] * 50)
    expect(result["omitted_fields"].size).to eq(50)
  end

  it "bounds database fields before materializing a large page" do
    organization
    50.times { |index| issue(source: "#{'a' * 400}_#{index}_t") }
    result = call_tool("list_issues", { limit: 50 })
    expect(response.body.bytesize).to be <= 128 * 1024
    expect(result.dig("result", "isError")).to be(false)
  end

  it "budgets encoded expansion and duplicated text separately from stored field bytes" do
    50.times { |index| organization.hosts.create!(external_id: "host-#{index}", hostname: "\n" * 500) }
    result = call_tool("list_hosts", { limit: 50 })
    expect(response.body.bytesize).to be <= 128 * 1024
    expect(result.dig("result", "structuredContent", "error", "code")).to eq("scope_exceeds_limit")
    expect(result.dig("result", "isError")).to be(true)
  end

  it "rejects an excessive stored-field page budget before fetching the permission arrays" do
    50.times do |index|
      item = issue(source: "budget_#{index}_t")
      item.update!(permissions: Array.new(16) { "x" * 128 })
    end
    statements = []
    subscription = ActiveSupport::Notifications.subscribe("sql.active_record") { |*, payload| statements << payload[:sql] }
    result = call_tool("list_issues", { limit: 50 })
    expect(result.dig("result", "structuredContent", "error", "code")).to eq("scope_exceeds_limit")
    expect(statements.join("\n")).not_to match(/THEN "?issues"?\."?permissions"? ELSE NULL END/)
  ensure
    ActiveSupport::Notifications.unsubscribe(subscription) if subscription
  end

  it "fetches the measured field versions when concurrent growth exceeds the aggregate budget" do
    items = 50.times.map { |index| issue(source: "growth_#{index}_t") }
    grown_permissions = Array.new(16) { "x" * 128 }
    projected_rows = nil
    grew = false
    allow_any_instance_of(McpInvestigation::Reader).to receive(:project).and_wrap_original do |original, *arguments|
      projected_rows = original.call(*arguments)
    end
    subscription = ActiveSupport::Notifications.subscribe("sql.active_record") do |*, payload|
      sql = payload[:sql]
      next if grew || !sql.start_with?("SELECT ") || !sql.include?('CAST("issues"."permissions" AS text)') || !sql.include?("ELSE 0 END")

      grew = true
      commit_concurrently { Issue.where(id: items.map(&:id)).update_all(permissions: grown_permissions) }
    end

    result = call_tool("list_issues", { limit: 50 }).fetch("result")
    expect(grew).to be(true)
    expect(projected_rows.sum { |row| JSON.generate(row.fetch(:permissions)).bytesize }).to be <= 64 * 1024
    expect(result["isError"]).to be(false)
    expect(result.dig("structuredContent", "data", "issues").map { |row| row.fetch("permissions") }).to eq(Array.new(50) { ["read"] })
    expect(items.first.reload.permissions).to eq(grown_permissions)
  ensure
    ActiveSupport::Notifications.unsubscribe(subscription) if subscription
  end

  it "discloses detected parent changes without claiming unchanged evidence" do
    item = issue
    2.times do |index|
      item.signatures.create!(fingerprint_version: 3, fingerprint_digest: "signature-#{index}",
        permissions: ["read"], first_seen_at: Time.current, last_seen_at: Time.current)
    end
    first = result_for("get_issue", { issue_id: item.id.to_s, limit: 1 })
    item.update!(updated_at: 1.minute.from_now)
    second = result_for("get_issue", { issue_id: item.id.to_s, cursor: first.dig("retrieval", "next_cursor") })
    expect(second.dig("retrieval", "change_detection")).to eq("changed")
  end

  it "returns explicit not-found rather than empty findings" do
    organization
    expect(call_tool("get_issue", { issue_id: "999" }).dig("result", "structuredContent", "error", "code")).to eq("not_found")
    expect(call_tool("get_host", { host_id: "9223372036854775808" }).dig("result", "structuredContent", "error", "code")).to eq("invalid_arguments")
  end

  it "enforces read-only transactions and cleans up pooled statement deadlines on failure" do
    item = issue
    allow_any_instance_of(McpInvestigation::Reader).to receive(:dispatch) { item.update_columns(status: "resolved") }
    expect(call_tool("get_overview").dig("result", "structuredContent", "error", "code")).to eq("internal_error")
    expect(item.reload.status).to eq("open")
    expect(ActiveRecord::Base.connection.select_value("SHOW transaction_read_only")).to eq("off")
    expect(ActiveRecord::Base.connection.select_value("SHOW statement_timeout")).to eq("0")
    expect(ActiveRecord::Base.connection.select_value("SHOW transaction_isolation")).to eq("read committed")
  end

  it "does not turn database timeouts into successful empty results" do
    organization
    allow_any_instance_of(McpInvestigation::Reader).to receive(:dispatch) { ActiveRecord::Base.connection.execute("SELECT pg_sleep(1.1)") }
    expect(call_tool("get_overview").dig("result", "structuredContent", "error", "code")).to eq("deadline_exceeded")
    expect(ActiveRecord::Base.connection.select_value("SHOW statement_timeout")).to eq("0")
  end

  it "logs neither credentials, unverified caller names nor request arguments" do
    log = StringIO.new
    allow(Rails).to receive(:logger).and_return(ActiveSupport::Logger.new(log))
    rpc("initialize", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "PRIVATE-CALLER", version: "1" } }, version: nil)
    call_tool("get_host", { host_id: "1", note: "PRIVATE-ARGUMENT" })
    expect(log.string).to include("integration=investigation")
    expect(log.string).not_to include("PRIVATE-", "investigation-test-token")
  end
end
