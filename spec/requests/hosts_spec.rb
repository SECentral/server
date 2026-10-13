require "rails_helper"

RSpec.describe "Hosts API", type: :request do
  before do
    Organization.create!(name: "hosts")
    sign_in_operator
  end

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
  end

  context "unauthenticated" do
    before do
      sign_in_operator
      sign_out_operator
    end

    it "rejects the host list, detail, and occurrences" do
      get "/api/v1/hosts"
      expect(response).to have_http_status(:unauthorized)
      expect(JSON.parse(response.body)).to include("error" => hash_including("code" => "unauthorized"))

      get "/api/v1/hosts/1"
      expect(response).to have_http_status(:unauthorized)

      get "/api/v1/hosts/1/occurrences"
      expect(response).to have_http_status(:unauthorized)
    end
  end

  it "lists hosts with agent state summary, per-host counts, and page metadata" do
    alma = observe_host("alma", {
      "platform" => { "os_id" => "almalinux", "os_version" => "9.3" },
      "selinux" => { "enforcement" => "enforcing", "configured_policy_type" => "targeted", "kernel_policy_version" => 33 }
    })
    AgentInstallation.create!(organization: alma.organization, name: "alma-agent", bound_host: alma, agent_version: "0.2.0", last_seen_at: Time.current)
    debian = observe_host("debian", {
      "platform" => { "os_id" => "debian", "os_version" => "12" },
      "selinux" => { "enforcement" => "permissive" }
    }, received_at: 20.minutes.ago)
    issue = create_issue
    create_occurrence(issue, alma)
    create_occurrence(issue, debian)

    get "/api/v1/hosts"

    body = JSON.parse(response.body)
    expect(response).to have_http_status(:ok)
    expect(body["hosts"].length).to eq(2)
    alma_item = body["hosts"].find { |item| item["id"] == alma.id }
    expect(alma_item).to include(
      "hostname" => "alma", "external_id" => "alma",
      "agent" => { "reporting_state" => "reporting", "agent_version" => "0.2.0", "last_seen_at" => kind_of(String) },
      "observation" => { "status" => "current", "last_received_at" => kind_of(String), "last_observed_at" => kind_of(String) },
      "platform" => { "os_id" => "almalinux", "os_version" => "9.3" },
      "selinux" => { "enforcement" => "enforcing", "configured_policy_type" => "targeted", "kernel_policy_version" => 33 },
      "counts" => { "active_issues" => 1, "avcs_24h" => 1, "total_events" => 1 }
    )
    expect(alma_item).not_to have_key("snapshot")
    expect(alma_item["selinux"]).not_to have_key("policy_identity")
    debian_item = body["hosts"].find { |item| item["id"] == debian.id }
    expect(debian_item["observation"]).to include("status" => "stale")
    expect(body["summary"]).to include("total" => 2, "agent_state_counts" => { "reporting" => 1, "stale" => 0, "offline" => 1 })
    expect(body["meta"]).to eq("page" => 1, "page_size" => 50, "total" => 2, "total_pages" => 1)
    expect(body).not_to have_key("boolean_inventory")
  end

  it "filters by os_id, policy_type, kernel_policy_version, and enforcement from the current snapshot" do
    alma = observe_host("filter-alma", {
      "platform" => { "os_id" => "almalinux" },
      "selinux" => { "enforcement" => "enforcing", "configured_policy_type" => "targeted", "kernel_policy_version" => 33 }
    })
    observe_host("filter-debian", {
      "platform" => { "os_id" => "debian" },
      "selinux" => { "enforcement" => "permissive", "configured_policy_type" => "targeted", "kernel_policy_version" => 41 }
    })

    get "/api/v1/hosts", params: { os_id: "almalinux" }
    expect(hostnames(response)).to eq(["filter-alma"])

    get "/api/v1/hosts", params: { policy_type: "targeted", kernel_policy_version: "41" }
    expect(hostnames(response)).to eq(["filter-debian"])

    get "/api/v1/hosts", params: { enforcement: "permissive" }
    expect(hostnames(response)).to eq(["filter-debian"])

    get "/api/v1/hosts", params: { os_id: "almalinux", enforcement: "permissive" }
    expect(hostnames(response)).to eq([])
  end

  it "keeps stale observations out of snapshot filters" do
    observe_host("stale-filter", {
      "platform" => { "os_id" => "almalinux" },
      "selinux" => { "enforcement" => "enforcing" }
    }, received_at: 20.minutes.ago)

    get "/api/v1/hosts", params: { os_id: "almalinux" }
    expect(hostnames(response)).to eq([])
  end

  it "filters by agent version and reporting state" do
    reporting = observe_host("agent-reporting", { "selinux" => {} })
    stale = observe_host("agent-stale", { "selinux" => {} })
    offline = observe_host("agent-offline", { "selinux" => {} })
    AgentInstallation.create!(organization: reporting.organization, name: "r", bound_host: reporting, agent_version: "0.2.0", last_seen_at: Time.current)
    AgentInstallation.create!(organization: stale.organization, name: "s", bound_host: stale, agent_version: "0.3.0", last_seen_at: 30.minutes.ago)
    AgentInstallation.create!(organization: offline.organization, name: "o", bound_host: offline, agent_version: "0.2.0", last_seen_at: 2.hours.ago)

    get "/api/v1/hosts", params: { agent_version: "0.2.0" }
    expect(hostnames(response)).to contain_exactly("agent-reporting", "agent-offline")

    get "/api/v1/hosts", params: { status: "stale" }
    expect(hostnames(response)).to eq(["agent-stale"])

    get "/api/v1/hosts", params: { status: "offline" }
    expect(hostnames(response)).to eq(["agent-offline"])
  end

  it "restricts the list to a single host by host_id" do
    selected = observe_host("selected", { "selinux" => {} })
    other = observe_host("other", { "selinux" => {} })

    get "/api/v1/hosts", params: { host_id: selected.id }

    expect(hostnames(response)).to eq(["selected"])
  end

  it "paginates the host list" do
    55.times do |index|
      observe_host("page-host-#{format('%02d', index)}", { "selinux" => { "enforcement" => "enforcing" } })
    end

    get "/api/v1/hosts"
    body = JSON.parse(response.body)
    expect(body["hosts"].length).to eq(50)
    expect(body["meta"]).to eq("page" => 1, "page_size" => 50, "total" => 55, "total_pages" => 2)

    get "/api/v1/hosts", params: { page: 2 }
    body = JSON.parse(response.body)
    expect(body["hosts"].length).to eq(5)
    expect(body["meta"]["page"]).to eq(2)
  end

  it "returns the host core detail with snapshot, policy identity, and counts" do
    host = observe_host("detail", {
      "platform" => { "os_id" => "almalinux", "os_version" => "9.3", "architecture" => "x86_64" },
      "selinux" => {
        "enforcement" => "enforcing", "configured_policy_type" => "targeted",
        "kernel_policy_version" => 33, "policy_identity" => "sha256:" + "a" * 64
      }
    })
    AgentInstallation.create!(organization: host.organization, name: "detail-agent", bound_host: host, agent_version: "0.2.0", last_seen_at: 5.minutes.ago)
    issue = create_issue
    occurrence = create_occurrence(issue, host)
    create_ungroupable_occurrence(host)

    get "/api/v1/hosts/#{host.id}"

    body = JSON.parse(response.body).fetch("host")
    expect(response).to have_http_status(:ok)
    expect(body).to include(
      "id" => host.id, "hostname" => "detail", "external_id" => "detail",
      "agent" => { "reporting_state" => "reporting", "agent_version" => "0.2.0", "last_seen_at" => kind_of(String) },
      "observation" => { "status" => "current", "last_received_at" => kind_of(String), "last_observed_at" => kind_of(String) },
      "platform" => { "os_id" => "almalinux", "os_version" => "9.3", "architecture" => "x86_64" },
      "selinux" => hash_including(
        "enforcement" => "enforcing", "configured_policy_type" => "targeted",
        "kernel_policy_version" => 33, "policy_identity" => "sha256:" + "a" * 64
      ),
      "counts" => { "active_issues" => 1, "avcs_24h" => 2, "total_events" => 2 }
    )
    expect(body["snapshot"]).to eq(
      "platform" => { "os_id" => "almalinux", "os_version" => "9.3", "architecture" => "x86_64" },
      "selinux" => body["selinux"]
    )
    expect(body.dig("selinux", "effective_permissive_domains")).to include("status" => "unavailable", "domains" => nil)
    expect(body).not_to have_key("booleans")
    expect(body["snapshot"]["selinux"]).not_to have_key("booleans")
    expect(body["snapshot"]["selinux"]).not_to have_key("boolean_status")
    expect(body["snapshot"]["selinux"]).not_to have_key("policy")
  end

  it "marks a stale observation and keeps the last-observed data visible" do
    observed_at = 2.hours.ago
    host = observe_host("stale-detail", { "selinux" => { "enforcement" => "permissive" } }, at: observed_at, received_at: 1.hour.ago)

    get "/api/v1/hosts/#{host.id}"

    body = JSON.parse(response.body).fetch("host")
    expect(body["observation"]).to include("status" => "stale")
    expect(body["observation"]["last_observed_at"]).to eq(observed_at.iso8601(3))
    expect(body["snapshot"]["selinux"]).to include("enforcement" => "permissive")
  end

  it "returns a nil snapshot without a heartbeat-confirmed observation" do
    host = Host.create!(organization: Organization.sole, external_id: "event-only", hostname: "event-only")
    HostSnapshot.create!(host: host, details: { "selinux" => { "enforcement" => "enforcing" } })

    get "/api/v1/hosts/#{host.id}"

    body = JSON.parse(response.body).fetch("host")
    expect(body["snapshot"]).to be_nil
    expect(body["observation"]).to eq("status" => "none", "last_received_at" => nil, "last_observed_at" => nil)
  end

  it "returns 404 for an unknown host" do
    get "/api/v1/hosts/999_999"
    expect(response).to have_http_status(:not_found)
    expect(JSON.parse(response.body)).to include("error" => hash_including("code" => "not_found"))

    get "/api/v1/hosts/999_999/occurrences"
    expect(response).to have_http_status(:not_found)
  end

  it "lists host occurrences newest first with issue links and escaped raw payloads" do
    issue = create_issue
    host = observe_host("occ-list", { "selinux" => {} })
    grouped = create_occurrence(issue, host, occurred_at: Time.current)
    ungrouped = create_ungroupable_occurrence(host, occurred_at: 2.hours.ago)
    grouped.raw_event.raw_audit_records.create!(position: 0, record_type: 1400, type_name: "avc", audit_timestamp: Time.current, sequence: 1, payload: '<script>alert("x")</script> type=AVC')

    get "/api/v1/hosts/#{host.id}/occurrences"

    body = JSON.parse(response.body)
    expect(response).to have_http_status(:ok)
    expect(body["occurrences"].map { |item| item["id"] }).to eq([grouped.id, ungrouped.id])
    grouped_item = body["occurrences"].first
    expect(grouped_item["issue"]).to eq("id" => issue.id)
    expect(grouped_item["guidance"]).to include("summary")
    expect(grouped_item["raw_event"]["audit_records"].first["payload"]).to eq('<script>alert("x")</script> type=AVC')
    ungrouped_item = body["occurrences"].last
    expect(ungrouped_item["issue"]).to be_nil
    expect(ungrouped_item["guidance"]).to be_nil
    expect(body["meta"]["next_cursor"]).to be_nil
  end

  it "pages host occurrences with a stable cursor for identical timestamps" do
    issue = create_issue
    host = observe_host("occ-page", { "selinux" => {} })
    fixed_time = Time.current.change(usec: 0)
    6.times { |index| create_occurrence(issue, host, occurred_at: fixed_time, sequence: index + 1) }

    first = JSON.parse(fetch_json("/api/v1/hosts/#{host.id}/occurrences?limit=4"))
    expect(first["occurrences"].length).to eq(4)
    expect(first["meta"]["next_cursor"]).to be_present
    first_ids = first["occurrences"].map { |item| item["id"] }

    second = JSON.parse(fetch_json("/api/v1/hosts/#{host.id}/occurrences?limit=4&before=#{first["meta"]["next_cursor"]}"))
    second_ids = second["occurrences"].map { |item| item["id"] }
    expect(second["occurrences"].length).to eq(2)
    expect(second_ids & first_ids).to be_empty
    expect(second["meta"]["next_cursor"]).to be_nil
    expect(first_ids + second_ids).to match_array(Occurrence.order(:id).last(6).map(&:id))
  end

  it "caps the occurrence page size at 50" do
    issue = create_issue
    host = observe_host("occ-cap", { "selinux" => {} })
    3.times { create_occurrence(issue, host) }

    body = JSON.parse(fetch_json("/api/v1/hosts/#{host.id}/occurrences?limit=99"))
    expect(body["meta"]["next_cursor"]).to be_nil
  end

  it "supports numbered pages, exact totals, size changes and out-of-range clamping" do
    issue = create_issue
    host = observe_host("numbered", { "selinux" => {} })
    fixed_time = Time.current.change(usec: 0)
    records = 26.times.map { |index| create_occurrence(issue, host, occurred_at: fixed_time, sequence: index + 1) }.reverse
    other = observe_host("other-numbered", { "selinux" => {} })
    create_occurrence(issue, other)

    first = JSON.parse(fetch_json("/api/v1/hosts/#{host.id}/occurrences?limit=10&page=1"))
    expect(first["meta"]).to include("page" => 1, "page_size" => 10, "total" => 26, "total_pages" => 3)
    expect(first["occurrences"].map { |item| item["id"] }).to eq(records.first(10).map(&:id))
    last = JSON.parse(fetch_json("/api/v1/hosts/#{host.id}/occurrences?limit=10&page=99"))
    expect(last["meta"]["page"]).to eq(3)
    expect(last["occurrences"].map { |item| item["id"] }).to eq(records.last(6).map(&:id))
    resized = JSON.parse(fetch_json("/api/v1/hosts/#{host.id}/occurrences?limit=25&page=2"))
    expect(resized["occurrences"].map { |item| item["id"] }).to eq([records.last.id])
  end

  it "returns page one for empty hosts and rejects invalid numbered pagination" do
    host = observe_host("empty-numbered", { "selinux" => {} })
    body = JSON.parse(fetch_json("/api/v1/hosts/#{host.id}/occurrences?page=3&limit=10"))
    expect(body["meta"]).to include("page" => 1, "total" => 0, "total_pages" => 0)
    [{ page: 0 }, { page: "" }, { page: "x" }, { page: "1.5" }, { page: 1, before: "cursor" }].each do |params|
      get "/api/v1/hosts/#{host.id}/occurrences", params: params
      expect(response).to have_http_status(:unprocessable_content)
    end
  end

  it "rejects an invalid occurrence cursor" do
    host = observe_host("occ-cursor", { "selinux" => {} })

    get "/api/v1/hosts/#{host.id}/occurrences", params: { before: "not-a-cursor" }

    expect(response).to have_http_status(:unprocessable_content)
    expect(JSON.parse(response.body)).to include("error" => hash_including("code" => "invalid_value"))
  end

  def hostnames(response)
    JSON.parse(response.body).fetch("hosts").map { |item| item["hostname"] }
  end

  def fetch_json(path)
    get path
    expect(response).to have_http_status(:ok)
    response.body
  end

  def observe_host(external_id, details, at: Time.current, received_at: at)
    organization = Organization.sole
    host = Host.create!(organization: organization, external_id: external_id, hostname: external_id)
    snapshot = HostSnapshot.create!(host: host, details: details)
    installation = AgentInstallation.create!(organization: organization, name: "obs-agent-#{external_id}", bound_host: host)
    host.host_snapshot_observations.create!(agent_installation: installation, host_snapshot: snapshot, first_observed_at: at, last_observed_at: at, first_received_at: received_at, last_received_at: received_at)
    host
  end

  def create_issue(digest = "digest-#{SecureRandom.hex(4)}")
    Issue.create!(organization: Organization.sole, fingerprint_version: 3,
      fingerprint_digest: digest, source_type: "httpd_t", target_type: "default_t",
      target_class: "file", permissions: ["read"], first_seen_at: Time.current,
      last_seen_at: Time.current)
  end

  def create_occurrence(issue, host, occurred_at: Time.current, sequence: 1)
    snapshot = host.current_snapshot
    raw_event = RawEvent.create!(organization: host.organization,
      agent_installation: host.agent_installations.first, host: host, host_snapshot: snapshot,
      audit_timestamp: occurred_at, audit_sequence: sequence, boot_id: "boot",
      completion_reason: "eoe", evidence_digest: "evidence-#{SecureRandom.hex(4)}",
      host_observed_at: occurred_at, agent_received_at: occurred_at, server_received_at: occurred_at, schema_version: 2)
    NormalizedDenial.create!(raw_event: raw_event, ordinal: 0, normalization_version: 1, status: "ok",
      source_type: "httpd_t", target_type: "default_t", target_class: "file", permissions: ["read"])
    issue.reload
    Occurrence.create!(organization: host.organization, host: host, host_snapshot: snapshot,
      raw_event: raw_event, normalized_denial: raw_event.normalized_denials.last, issue: issue, occurred_at: occurred_at)
  end

  def create_ungroupable_occurrence(host, occurred_at: Time.current)
    snapshot = host.current_snapshot
    raw_event = RawEvent.create!(organization: host.organization,
      agent_installation: host.agent_installations.first, host: host, host_snapshot: snapshot,
      audit_timestamp: occurred_at, audit_sequence: 2, boot_id: "boot",
      completion_reason: "eoe", evidence_digest: "evidence-#{SecureRandom.hex(4)}",
      host_observed_at: occurred_at, agent_received_at: occurred_at, server_received_at: occurred_at, schema_version: 2)
    NormalizedDenial.create!(raw_event: raw_event, ordinal: 0, normalization_version: 1, status: "ok")
    Occurrence.create!(organization: host.organization, host: host, host_snapshot: snapshot,
      raw_event: raw_event, normalized_denial: raw_event.normalized_denials.last, occurred_at: occurred_at)
  end
end
