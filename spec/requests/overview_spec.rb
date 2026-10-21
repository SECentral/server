require "rails_helper"

RSpec.describe "Overview API", type: :request do
  after do
    Occurrence.delete_all
    NormalizedDenial.delete_all
    IssueDispositionChange.delete_all
    Issue.delete_all
    RawAuditRecord.delete_all
    RawEvent.delete_all
    HostSnapshotObservation.delete_all
    HostSnapshot.delete_all
    AgentInstallation.delete_all
    Host.delete_all
    Organization.delete_all
    DistributionCatalogImport.delete_all
    DistributionCatalogBoolean.delete_all
    DistributionCatalogPort.delete_all
    DistributionCatalogRevision.delete_all
  end

  it "requires an authenticated operator" do
    get "/api/v1/overview"

    expect(response).to have_http_status(:unauthorized)
  end

  it "serves the SPA shell at the root path" do
    get "/"

    expect(response).to have_http_status(:ok)
    expect(response.body).to include('<div id="root">')
  end

  it "returns dashboard aggregates, 7-day series, and attention items" do
    sign_in_operator
    organization = Organization.create!(name: "overview")
    host1 = Host.create!(organization: organization, external_id: "ovr-01", hostname: "overview-01")
    host2 = Host.create!(organization: organization, external_id: "ovr-02", hostname: "overview-02")
    AgentInstallation.create!(organization: organization, name: "agent-01", bound_host: host1, last_seen_at: 5.minutes.ago)
    AgentInstallation.create!(organization: organization, name: "agent-02", bound_host: host2, last_seen_at: 30.minutes.ago)
    observe(host1, { "selinux" => { "enforcement" => "permissive" } })

    issue_a = create_issue("digest-a", first_seen_at: 30.minutes.ago, last_seen_at: 30.minutes.ago)
    create_occurrence(issue_a, host1, 10.minutes.ago)
    create_occurrence(issue_a, host2, 5.minutes.ago)
    create_issue("digest-b", first_seen_at: 3.days.ago, last_seen_at: 3.days.ago)

    get "/api/v1/overview"

    expect(response).to have_http_status(:ok)
    payload = JSON.parse(response.body)
    expect(payload["metrics"]).to eq(
      "active_issues" => 2,
      "new_issues_24h" => 1,
      "affected_hosts" => 2,
      "avcs_24h" => 2,
      "monitored_hosts" => 2,
      "agent_states" => { "reporting" => 1, "stale" => 1, "offline" => 0 }
    )

    new_issue_series = payload["series"]["new_issues"]
    expect(new_issue_series.size).to eq(7)
    expect(new_issue_series.last).to eq("date" => Date.current.iso8601, "value" => 1)
    expect(new_issue_series[3]).to eq("date" => 3.days.ago.to_date.iso8601, "value" => 1)
    expect(new_issue_series.sum { |point| point["value"] }).to eq(2)
    avc_series = payload["series"]["avc_occurrences"]
    expect(avc_series.size).to eq(7)
    expect(avc_series.last).to eq("date" => Date.current.iso8601, "value" => 2)

    attention = payload["attention"]
    expect(attention["agent_states"].size).to eq(1)
    stale_group = attention["agent_states"].first
    expect(stale_group["state"]).to eq("stale")
    expect(stale_group["host_count"]).to eq(1)
    expect(stale_group["example_hosts"]).to eq([{ "id" => host2.id, "hostname" => "overview-02" }])
    expect(stale_group["heartbeat_range"].map { |timestamp| Time.parse(timestamp) })
      .to all(be_between(35.minutes.ago, 25.minutes.ago))
    expect(attention["permissive"]).to eq(
      "host_count" => 1,
      "example_hosts" => [{ "id" => host1.id, "hostname" => "overview-01" }]
    )
    expect(attention["new_issues"]).to eq(
      "issue_count" => 1,
      "example_issues" => [{ "id" => issue_a.id, "source_type" => "httpd_t", "target_type" => "default_t" }]
    )
    expect(attention["multi_host_issues"]).to eq(
      "issue_count" => 1,
      "example_issues" => [{ "id" => issue_a.id, "source_type" => "httpd_t", "target_type" => "default_t" }]
    )
  end

  it "loads agent installations once for metrics and attention as the fleet grows" do
    sign_in_operator
    organization = Organization.create!(name: "overview-query-count")
    [1, 4].each do |additional_hosts|
      additional_hosts.times do
        host = organization.hosts.create!(external_id: SecureRandom.uuid)
        organization.agent_installations.create!(name: host.external_id, bound_host: host, last_seen_at: 30.minutes.ago)
      end
      queries = []
      subscriber = ActiveSupport::Notifications.subscribe("sql.active_record") do |event|
        queries << event.payload[:sql] if event.payload[:sql].include?('FROM "agent_installations"')
      end
      begin
        get "/api/v1/overview"
      ensure
        ActiveSupport::Notifications.unsubscribe(subscriber)
      end

      expect(response).to have_http_status(:ok)
      expect(queries.size).to eq(1)
      body = JSON.parse(response.body)
      expect(body.dig("metrics", "agent_states", "stale")).to eq(organization.hosts.count)
      expect(body.dig("attention", "agent_states", 0, "host_count")).to eq(organization.hosts.count)
    end
  end

  it "does not present stale permissive configuration as current despite recent host activity" do
    sign_in_operator
    organization = Organization.create!(name: "stale-permissive-overview")
    host = Host.create!(organization: organization, external_id: "stale-permissive", hostname: "stale-permissive")
    AgentInstallation.create!(organization: organization, name: "agent", bound_host: host, last_seen_at: 5.minutes.ago)
    observe(host, { "selinux" => { "enforcement" => "permissive" } }, at: 2.hours.ago, received_at: 1.hour.ago)

    get "/api/v1/overview"

    expect(JSON.parse(response.body).dig("attention", "permissive")).to be_nil
  end

  it "reports an empty attention section when nothing needs attention" do
    sign_in_operator
    organization = Organization.create!(name: "quiet-fleet")
    host = Host.create!(organization: organization, external_id: "quiet", hostname: "quiet-01")
    AgentInstallation.create!(organization: organization, name: "agent", bound_host: host, last_seen_at: 5.minutes.ago)
    observe(host, { "selinux" => { "enforcement" => "enforcing" } })

    get "/api/v1/overview"

    expect(JSON.parse(response.body)["attention"]).to eq(
      "agent_states" => [],
      "permissive" => nil,
      "new_issues" => nil,
      "multi_host_issues" => nil
    )
  end

  def observe(host, details, at: Time.current, received_at: at)
    snapshot = HostSnapshot.create!(host: host, details: details)
    installation = host.agent_installations.first ||
      host.organization.agent_installations.create!(name: "snapshot-agent-#{host.external_id}", bound_host: host)
    host.host_snapshot_observations.create!(
      agent_installation: installation, host_snapshot: snapshot,
      first_observed_at: at, last_observed_at: at, first_received_at: received_at, last_received_at: received_at
    )
    snapshot
  end

  def create_issue(digest, **attributes)
    Issue.create!({
      organization: Organization.create!(name: "overview org #{SecureRandom.hex(4)}"),
      fingerprint_version: 3,
      fingerprint_digest: digest,
      source_type: "httpd_t",
      target_type: "default_t",
      target_class: "file",
      permissions: ["read"],
      first_seen_at: Time.current,
      last_seen_at: Time.current
    }.merge(attributes))
  end

  def create_occurrence(issue, host, occurred_at)
    snapshot = HostSnapshot.create!(host: host, details: { "id" => host.external_id })
    installation = host.organization.agent_installations.first ||
      AgentInstallation.create!(organization: issue.organization, name: "occ-agent-#{host.external_id}")
    raw_event = RawEvent.create!(
      organization: issue.organization, agent_installation: installation, host: host, host_snapshot: snapshot,
      audit_timestamp: occurred_at, audit_sequence: 1, boot_id: "boot-#{host.external_id}",
      completion_reason: "eoe", evidence_digest: "ovr-digest-#{host.external_id}",
      host_observed_at: Time.current, agent_received_at: Time.current, server_received_at: Time.current, schema_version: 2
    )
    denial = NormalizedDenial.create!(
      raw_event: raw_event, ordinal: 0, normalization_version: 1, status: "ok",
      source_type: "httpd_t", target_type: "default_t", target_class: "file", permissions: ["read"]
    )
    Occurrence.create!(
      organization: issue.organization, host: host, host_snapshot: snapshot,
      raw_event: raw_event, normalized_denial: denial, issue: issue, occurred_at: occurred_at
    )
  end
end
