require "rails_helper"

RSpec.describe "Prometheus domain metrics", type: :request do
  let(:headers) { { "Authorization" => "Bearer metrics-test-token" } }

  around do |example|
    previous = ENV["SECENTRAL_METRICS_TOKEN"]
    ENV["SECENTRAL_METRICS_TOKEN"] = "metrics-test-token"
    # Committed fixtures from other specs must not affect installation-wide counts.
    [Occurrence.unscoped, NormalizedDenial, IssueDispositionChange, IssueSignature, Issue,
      RawAuditRecord, RawEvent, HostSnapshotObservation, HostSnapshot, HostReportingDay,
      AgentInstallation, Host, Organization].each(&:delete_all)
    ActiveRecord::Base.transaction do
      example.run
      raise ActiveRecord::Rollback
    end
  ensure
    ENV["SECENTRAL_METRICS_TOKEN"] = previous
  end

  ["/metrics", "/metrics/"].each do |path|
    it "serves #{path} directly as uncached Prometheus text, including empty series" do
      get path, headers: headers.merge("Accept" => "application/json")
      expect(response).to have_http_status(:ok)
      expect(response.headers["Content-Type"]).to eq("text/plain; version=0.0.4; charset=utf-8")
      expect(response.headers["Cache-Control"]).to eq("no-store")
      expect(response.body).to include('secentral_issues{status="open",disposition="mixed"} 0',
        'secentral_hosts_by_selinux_enforcement{state="disabled"} 0', "secentral_hosts 0\n")
      expect(response.body).not_to include('<div id="root">')
    end

    [nil, "", " \t\n"].each do |configured|
      it "disables #{path} with #{configured.inspect} configuration before querying" do
        ENV["SECENTRAL_METRICS_TOKEN"] = configured
        expect(DomainMetricsQuery).not_to receive(:new)
        get path, headers: headers
        expect(response).to have_http_status(:not_found)
        expect(response.body).to be_empty
      end
    end

    ["bearer", "bEaReR", "Bearer ", "bEaReR   "].each do |scheme|
      it "accepts #{scheme.inspect} scheme casing and separator spacing at #{path}" do
        get path, headers: { "Authorization" => "#{scheme} metrics-test-token" }
        expect(response).to have_http_status(:ok)
      end
    end

    [nil, "Bearer wrong", "Bearer test-ingestion-key", "Basic credentials", "Bearer metrics-test-token extra",
      "bearer  metrics-test-token extra", "Bearer METRICS-TEST-TOKEN", "Bearer\tmetrics-test-token"].each do |authorization|
      it "rejects #{authorization.inspect} at #{path} before querying" do
        expect(DomainMetricsQuery).not_to receive(:new)
        get path, headers: { "Authorization" => authorization }.compact
        expect(response).to have_http_status(:unauthorized)
        expect(response.headers["WWW-Authenticate"]).to eq('Bearer realm="metrics"')
        expect(response.headers["Cache-Control"]).to eq("no-store")
        expect(response.body).to be_empty
      end
    end
  end

  it "exports actual populated database counts rather than only empty series" do
    organization = Organization.create!(name: "metrics-response")
    first, second = %w[first second].map { |id| organization.hosts.create!(external_id: id) }
    installation = organization.agent_installations.create!(name: "metrics-agent", bound_host: first, last_seen_at: Time.current)
    opened, resolved = [["open", "suspicious_behavior"], ["resolved", "expected_harmless"]].map do |status, disposition|
      organization.issues.create!(fingerprint_version: 3, fingerprint_digest: status, source_type: "#{status}_t",
        target_type: "target_t", target_class: "file", status: status, disposition: disposition,
        first_seen_at: Time.current, last_seen_at: Time.current)
    end
    opened.update!(reopened_at: Time.current)
    2.times { create_occurrence(first, installation, issue: opened) }
    create_occurrence(second, installation, issue: resolved)
    create_occurrence(second, installation, issue: nil)
    create_occurrence(second, installation, issue: opened, superseded_at: Time.current)

    get "/metrics", headers: headers

    expect(response).to have_http_status(:ok)
    expect(response.body.lines.map(&:chomp)).to include(
      'secentral_issues{status="open",disposition="suspicious_behavior"} 1',
      'secentral_issues{status="resolved",disposition="expected_harmless"} 1',
      "secentral_regressed_issues 1", "secentral_occurrences 4", "secentral_ungrouped_occurrences 1",
      "secentral_hosts 2", 'secentral_hosts_by_selinux_enforcement{state="unknown"} 2',
      "secentral_hosts_with_open_issues 1", 'secentral_agent_installations{state="reporting"} 1')
  end

  it "does not use browser authentication or normalize configured nonblank tokens" do
    sign_in_operator
    get "/metrics"
    expect(response).to have_http_status(:unauthorized)
    ENV["SECENTRAL_METRICS_TOKEN"] = " metrics-test-token "
    get "/metrics", headers: headers
    expect(response).to have_http_status(:unauthorized)
  end

  it "authenticates HEAD requests and returns no body" do
    head "/metrics"
    expect(response).to have_http_status(:unauthorized)
    head "/metrics/", headers: headers
    expect(response).to have_http_status(:ok)
    expect(response.body).to be_empty
  end

  it "reserves descendants and unsupported verbs instead of serving the SPA" do
    get "/metrics/anything", headers: headers
    expect(response).to have_http_status(:not_found)
    post "/metrics", headers: headers
    expect(response).to have_http_status(:not_found)
  end

  it "fails the scrape on query failure rather than exporting zeros or partial results" do
    allow_any_instance_of(DomainMetricsQuery).to receive(:call).and_raise(ActiveRecord::StatementInvalid, "query failed")
    expect { get "/metrics", headers: headers }.to raise_error(ActiveRecord::StatementInvalid)
    environment = Rails.application.env_config
    saved = environment.slice("action_dispatch.show_exceptions", "action_dispatch.show_detailed_exceptions")
    environment["action_dispatch.show_exceptions"] = :all
    environment["action_dispatch.show_detailed_exceptions"] = false
    get "/metrics", headers: headers
    expect(response).to have_http_status(:internal_server_error)
    expect(response.body).not_to include("secentral_issues", "metrics-test-token")
  ensure
    environment&.merge!(saved) if saved
  end

  def create_occurrence(host, installation, issue:, superseded_at: nil)
    now = Time.current
    raw = RawEvent.create!(organization: host.organization, host: host, agent_installation: installation,
      audit_timestamp: now, audit_sequence: RawEvent.count + 1, boot_id: "boot", completion_reason: "eoe",
      evidence_digest: SecureRandom.hex, agent_received_at: now, server_received_at: now, schema_version: 4)
    denial = NormalizedDenial.create!(raw_event: raw, ordinal: 0, normalization_version: 1, status: "ok")
    Occurrence.create!(organization: host.organization, host: host, raw_event: raw,
      normalized_denial: denial, issue: issue, occurred_at: now, superseded_at: superseded_at)
  end
end
