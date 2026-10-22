require "rails_helper"

RSpec.describe "Issues API", type: :request do
  before do
    Organization.create!(name: "issues")
    sign_in_operator
  end

  after do
    Occurrence.delete_all
    NormalizedDenial.delete_all
    PolicyFact.delete_all
    PolicyArtifact.delete_all
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

    it "rejects the issue list and ungroupable events" do
      get "/api/v1/issues"
      expect(response).to have_http_status(:unauthorized)
      expect(JSON.parse(response.body)).to include("error" => hash_including("code" => "unauthorized"))

      get "/api/v1/ungroupable-events"
      expect(response).to have_http_status(:unauthorized)
    end
  end

  it "lists issues with list-level summary, host options, and page metadata" do
    issue = create_issue
    create_occurrence(issue)
    other = create_issue
    other.update!(status: "resolved", resolved_at: Time.current)
    observe_host("enforcing-host", { "selinux" => { "enforcement" => "enforcing" } })
    observe_host("permissive-host", { "selinux" => { "enforcement" => "permissive" } })
    create_ungroupable_event("ungroupable-host")

    get "/api/v1/issues"

    body = JSON.parse(response.body)
    expect(response).to have_http_status(:ok)
    expect(body["issues"].length).to eq(1)
    item = body.fetch("issues").first
    expect(item).to include(
      "id" => issue.id, "status" => "open", "display_status" => "open", "disposition" => "unclassified",
      "source_type" => "httpd_t", "target_type" => "default_t", "target_class" => "file", "permissions" => ["read"],
      "fingerprint_version" => 4, "fingerprint_digest" => issue.fingerprint_digest,
      "occurrences_count" => 1, "hosts_count" => 1,
      "hosts" => [{ "id" => issue.occurrences.first.host_id, "hostname" => "web-1" }],
      "observed_paths" => []
    )
    expect(item).to have_key("first_seen_at")
    expect(item).to have_key("last_seen_at")
    expect(body.fetch("host_options").map { |host| host["hostname"] }).to eq(["enforcing-host", "permissive-host", "ungroupable-host", "web-1"])
    expect(body.fetch("meta")).to eq("page" => 1, "page_size" => 25, "total" => 1, "total_pages" => 1)
    expect(body.fetch("summary")).to include(
      "total_count" => 1, "open_count" => 1, "regressed_count" => 0, "ungroupable_count" => 1,
      "monitored_hosts" => 4, "enforcing_hosts" => 1, "enforcement_percent" => 25
    )
  end

  it "uses current host observations for the list summary without loading snapshot history" do
    host = observe_host("summary-history", { "selinux" => { "enforcement" => "enforcing" } })
    installation = host.agent_installations.first
    snapshot = host.host_snapshots.create!(details: { "selinux" => { "enforcement" => "permissive" } })
    at = 1.hour.ago
    host.host_snapshot_observations.create!(agent_installation: installation, host_snapshot: snapshot,
      first_observed_at: at, last_observed_at: at, first_received_at: at, last_received_at: at)
    queries = []
    subscriber = ActiveSupport::Notifications.subscribe("sql.active_record") { |event| queries << event.payload[:sql] }
    begin
      get "/api/v1/issues"
    ensure
      ActiveSupport::Notifications.unsubscribe(subscriber)
    end

    expect(response).to have_http_status(:ok)
    body = JSON.parse(response.body)
    expect(body.fetch("host_options")).to eq([{ "id" => host.id, "hostname" => "summary-history" }])
    expect(body.fetch("summary")).to include("monitored_hosts" => 1, "enforcing_hosts" => 1, "enforcement_percent" => 100)
    expect(queries).not_to include(a_string_matching(/FROM "host_snapshots" WHERE "host_snapshots"\."host_id" IN/))
  end

  it "excludes resolved issues by default and includes them under status=all" do
    open_issue = create_issue
    resolved_issue = create_issue("resolved-digest")
    resolved_issue.update!(status: "resolved", resolved_at: Time.current)

    get "/api/v1/issues"
    expect(JSON.parse(response.body).fetch("issues").map { |item| item["id"] }).to eq([open_issue.id])

    get "/api/v1/issues", params: { status: "all" }
    expect(JSON.parse(response.body).fetch("issues").length).to eq(2)

    get "/api/v1/issues", params: { status: "resolved" }
    expect(JSON.parse(response.body).fetch("issues").map { |item| item["id"] }).to eq([resolved_issue.id])
  end

  it "filters regressed issues through the regressed pseudo-status" do
    regressed = create_issue
    regressed.update!(resolved_at: 2.days.ago, reopened_at: 1.day.ago, regressions_count: 1)
    plain = create_issue("plain-digest")
    stale_reopen = create_issue("stale-reopen")
    stale_reopen.update!(status: "open", resolved_at: 1.day.ago, reopened_at: 2.days.ago)

    get "/api/v1/issues", params: { status: "regressed" }
    expect(JSON.parse(response.body).fetch("issues").map { |item| item["id"] }).to eq([regressed.id])

    get "/api/v1/issues"
    body = JSON.parse(response.body)
    regressed_item = body["issues"].find { |item| item["id"] == regressed.id }
    expect(regressed_item).to include("display_status" => "regressed", "status" => "open")
    expect(body.fetch("summary", {}).fetch("regressed_count", nil)).to eq(1)
  end

  it "filters by search text, host, permission, and lifecycle flags" do
    web_issue = create_issue
    create_occurrence(web_issue)
    web_issue.occurrences.first.normalized_denial.update!(target_paths: ["/srv/app/data"])
    nginx_issue = create_issue("nginx-digest", "nginx_t")
    create_occurrence(nginx_issue, "host-9")

    get "/api/v1/issues", params: { q: "nginx_t" }
    expect(JSON.parse(response.body).fetch("issues").map { |item| item["id"] }).to eq([nginx_issue.id])

    get "/api/v1/issues", params: { q: "web-1" }
    expect(JSON.parse(response.body).fetch("issues").map { |item| item["id"] }).to eq([web_issue.id])

    get "/api/v1/issues", params: { path: "/srv/app/data" }
    expect(JSON.parse(response.body).fetch("issues").map { |item| item["id"] }).to eq([web_issue.id])

    get "/api/v1/issues", params: { host_id: web_issue.occurrences.first.host_id }
    expect(JSON.parse(response.body).fetch("issues").map { |item| item["id"] }).to eq([web_issue.id])

    get "/api/v1/issues", params: { permission: "read" }
    expect(JSON.parse(response.body).fetch("issues").map { |item| item["id"] }).to include(web_issue.id, nginx_issue.id)

    get "/api/v1/issues", params: { permission: "write" }
    expect(JSON.parse(response.body).fetch("issues")).to be_empty

    get "/api/v1/issues", params: { new: "1" }
    expect(JSON.parse(response.body).fetch("issues").map { |item| item["id"] }).to include(web_issue.id, nginx_issue.id)

    old_issue = create_issue("old-digest")
    old_issue.update!(first_seen_at: 2.days.ago)
    get "/api/v1/issues", params: { new: "true" }
    expect(JSON.parse(response.body).fetch("issues").map { |item| item["id"] }).not_to include(old_issue.id)

    multi = create_issue("multi-digest")
    create_occurrence(multi, "multi-host-1")
    create_occurrence(multi, "multi-host-2")
    get "/api/v1/issues", params: { multiple_hosts: "1" }
    expect(JSON.parse(response.body).fetch("issues").map { |item| item["id"] }).to eq([multi.id])
  end

  it "lists retained ungroupable events, most recent first, with the host filter" do
    first = create_ungroupable_event("group-host", occurred_at: 2.hours.ago)
    second = create_ungroupable_event("other-host", occurred_at: 1.hour.ago)

    get "/api/v1/ungroupable-events"
    body = JSON.parse(response.body)
    expect(response).to have_http_status(:ok)
    expect(body["total_count"]).to eq(2)
    expect(body["events"].map { |item| item["id"] }).to eq([second.id, first.id])
    event = body["events"].first
    expect(event).to include("missing" => ["scontext"], "host" => include("hostname" => "other-host"))
    expect(event).to have_key("occurred_at")

    get "/api/v1/ungroupable-events", params: { host_id: first.host_id }
    body = JSON.parse(response.body)
    expect(body["events"].map { |item| item["id"] }).to eq([first.id])
  end

  it "shows the issue detail core with intelligence summary, diagnosis, and triage" do
    issue = create_issue
    create_occurrence(issue)
    create_occurrence(issue, "host-a", 2)
    issue.set_disposition!("under_investigation", note: "Reviewing the host change")

    get "/api/v1/issues/#{issue.id}"

    body = JSON.parse(response.body)
    expect(response).to have_http_status(:ok)
    expect(body.fetch("issue")).to include(
      "id" => issue.id, "occurrences_count" => 2, "affected_hosts" => 2,
        "status" => "open", "display_status" => "open", "disposition" => "under_investigation",
        "fingerprint_version" => 4, "fingerprint_digest" => issue.fingerprint_digest
    )
    expect(body.dig("issue", "disposition_history", 0)).to include("note" => "Reviewing the host change", "previous_disposition" => "unclassified", "disposition" => "under_investigation")
    expect(body.fetch("intelligence")).to include("affected_hosts" => 2)
    expect(body.fetch("intelligence")).to have_key("paths")
    expect(body.fetch("intelligence")).to have_key("occurrence_time")
    expect(body.fetch("intelligence")).to have_key("fleet")
    expect(body).to have_key("diagnosis")
    expect(body.fetch("host_explanations").length).to eq(2)
    expect(body.fetch("host_explanations")).to all(include("status" => "insufficient_evidence"))
    expect(body.fetch("fleet_explanation")).to include("state" => "insufficient_evidence", "affected_host_count" => 2)
    expect(body.fetch("policy_analysis")).to include("status" => "unavailable")
    expect(body.fetch("policy_analysis")).to have_key("limitations")
    expect(body.dig("host_explanations", 0, "diagnosis_groups", 0)).not_to have_key("agreement_signature")
    expect(body.fetch("triage")).to include("signals", "windows", "evaluated_at")
  end

  it "returns the AVC-versus-inspection file-context diagnosis from the detail core" do
    issue = create_issue(target_type: "var_t")
    occurrence = create_occurrence(issue)
    occurrence.normalized_denial.update!(
      target_context: "unconfined_u:object_r:var_t:s0",
      details: { "target_evidence" => { "filesystem_paths" => ["/srv/app/data"], "object_names" => [] } }
    )
    occurrence.raw_event.update!(file_context_observations: [{
      "kind" => "expected_context", "path" => "/srv/app/data", "object_class" => "file", "file_type" => "file",
      "status" => "resolved", "expected_context" => "system_u:object_r:custom_data_t:s0",
      "observed_at" => Time.current.iso8601(6), "resolver" => "matchpathcon"
    }])

    get "/api/v1/issues/#{issue.id}"

    diagnosis = JSON.parse(response.body).fetch("diagnosis")
    expect(diagnosis).to include("kind" => "file_context_mismatch", "observed_type" => "var_t", "expected_type" => "custom_data_t", "temporal_scope" => "avc_vs_expected_context_inspection")
    expect(diagnosis.fetch("interpretation")).to include("inspected the path")
    expect(diagnosis.fetch("limitation")).to include("after the AVC")
    expect(diagnosis.to_json).not_to include("web content", "web-server", "Apache", "MariaDB")
  end

  it "returns server-generated label inspection and restoration guidance from AVC paths" do
    issue = create_issue(target_type: "user_home_t")
    occurrence = create_occurrence(issue)
    occurrence.normalized_denial.update!(
      target_context: "unconfined_u:object_r:user_home_t:s0",
      details: { "target_evidence" => { "filesystem_paths" => ["/var/www/html/a file.txt"], "object_names" => ["a file.txt"] } }
    )

    get "/api/v1/issues/#{issue.id}"

    guidance = JSON.parse(response.body).fetch("triage_guidance")
    expect(guidance).to include("type" => "probable_label_mismatch", "path" => "/var/www/html/a file.txt", "observed_type" => "user_home_t", "conventional_type" => "httpd_sys_content_t")
    expect(guidance.fetch("commands").map { |command| command.fetch("command") }).to eq([
      "matchpathcon -- /var/www/html/a\\ file.txt",
      "restorecon -v -- /var/www/html/a\\ file.txt",
      "restorecon -Rv -- /var/www/html"
    ])
    body = JSON.parse(response.body)
    expect(body["diagnosis"]).to be_nil
    expect(body["findings"]).to eq([])
    expect(body["finding_coverage"]).to eq("unexplained" => 1)
    expect(body.dig("issue", "disposition")).to eq("unclassified")
    expect(body.dig("resolutions", "intent")).to be_nil
    operator = body.fetch("operator_guidance")
    expect(operator.fetch("source")).to include("occurrence_id" => occurrence.id, "host_id" => occurrence.host_id, "path" => guidance.fetch("path"))
    expect(operator.fetch("checks").map { |item| item.fetch("command") }).to include("ls -ldZ -- /var/www/html/a\\ file.txt", "restorecon -n -v -- /var/www/html/a\\ file.txt")
    expect(operator).not_to have_key("current_label")
    expect(operator.fetch("verification_limit")).to include("event-delivery health")
  end

  it "suppresses the lead for an eligible authoritative observation but ignores ineligible samples" do
    issue = create_issue(target_type: "user_home_t")
    occurrence = create_occurrence(issue)
    path = "/var/www/html/file.txt"
    occurrence.normalized_denial.update!(target_context: "unconfined_u:object_r:user_home_t:s0",
      details: { "target_evidence" => { "filesystem_paths" => [path] } })
    observation = { "kind" => "expected_context", "path" => path, "object_class" => "file", "file_type" => "file",
      "status" => "resolved", "expected_context" => "system_u:object_r:user_home_t:s0",
      "observed_at" => Time.current.iso8601(6), "resolver" => "matchpathcon" }
    occurrence.raw_event.update!(file_context_observations: [observation])

    get "/api/v1/issues/#{issue.id}"
    expect(JSON.parse(response.body).fetch("triage_guidance")).to be_nil

    occurrence.raw_event.update!(file_context_observations: [observation.merge("expected_context" => "system_u:object_r:custom_web_t:s0")])
    get "/api/v1/issues/#{issue.id}"
    expect(JSON.parse(response.body).fetch("triage_guidance")).to be_nil

    occurrence.raw_event.update!(file_context_observations: [observation.merge("observed_at" => (occurrence.occurred_at - 1.second).iso8601(6))])
    get "/api/v1/issues/#{issue.id}"
    expect(JSON.parse(response.body).dig("triage_guidance", "type")).to eq("probable_label_mismatch")

    [
      observation.merge("observed_at" => occurrence.occurred_at.iso8601(6)),
      observation.merge("object_class" => "dir"),
      observation.merge("path" => "/var/www/html/unrelated.txt"),
      observation.merge("status" => "unavailable", "expected_context" => nil)
    ].each do |ineligible|
      occurrence.raw_event.update!(file_context_observations: [ineligible])
      get "/api/v1/issues/#{issue.id}"
      expect(JSON.parse(response.body).dig("triage_guidance", "type")).to eq("probable_label_mismatch")
    end

    occurrence.raw_event.update!(file_context_observations: [observation], checkpoint_invalidated_fields: ["file_context_mappings"])
    get "/api/v1/issues/#{issue.id}"
    expect(JSON.parse(response.body).dig("triage_guidance", "type")).to eq("probable_label_mismatch")
  end

  it "suppresses conflicting eligible host results without assigning authoritative convention fields" do
    issue = create_issue(target_type: "user_home_t")
    path = "/srv/app/data"
    %w[custom_a_t custom_b_t].each_with_index do |type, index|
      occurrence = create_occurrence(issue, "host-#{index + 1}", index + 1)
      occurrence.normalized_denial.update!(target_context: "unconfined_u:object_r:user_home_t:s0",
        details: { "target_evidence" => { "filesystem_paths" => [path] } })
      occurrence.raw_event.update!(file_context_observations: [{ "kind" => "expected_context", "path" => path,
        "object_class" => "file", "status" => "resolved", "expected_context" => "system_u:object_r:#{type}:s0",
        "observed_at" => Time.current.iso8601(6), "resolver" => "matchpathcon" }])
    end

    get "/api/v1/issues/#{issue.id}"
    body = JSON.parse(response.body)
    expect(body["triage_guidance"]).to be_nil
    expect(body.dig("diagnosis", "kind")).to eq("file_context_mismatch")
    expect(body.dig("diagnosis", "expected_type")).to be_in(%w[custom_a_t custom_b_t])
  end

  it "keeps selected-occurrence labeling scope distinct from issue-wide resource counts" do
    issue = create_issue(target_type: "user_home_t")
    paths = ["/var/www/html/a.txt", "/var/www/html/b.txt", "/var/www/html-other/c.txt"]
    (paths + [paths.last]).each_with_index do |path, index|
      occurrence = create_occurrence(issue, "host-#{index + 1}", index + 1)
      occurrence.normalized_denial.update!(details: { "target_evidence" => { "filesystem_paths" => [path] } })
    end

    get "/api/v1/issues/#{issue.id}"
    body = JSON.parse(response.body)
    guidance = body.fetch("triage_guidance")
    expect(body.dig("intelligence", "resource_summary", "path_count")).to eq(3)
    expect(guidance).to include("path" => paths.last, "path_count" => 1,
      "recursive_directory" => "/var/www/html-other", "recursive_path_count" => 1)
    expect(guidance).not_to have_key("occurrence_count")
    expect(guidance).not_to have_key("expected_type")
  end

  it "lists occurrences with normalized denial, raw evidence, and per-occurrence guidance" do
    issue = create_issue
    occurrence = create_occurrence(issue)
    occurrence.raw_event.raw_audit_records.create!(
      position: 0, record_type: 1400, type_name: "avc", audit_timestamp: occurrence.raw_event.audit_timestamp,
      sequence: 1, payload: "type=AVC scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:default_t:s0"
    )

    get "/api/v1/issues/#{issue.id}/occurrences"

    body = JSON.parse(response.body)
    expect(response).to have_http_status(:ok)
    expect(body["occurrences"].length).to eq(1)
    item = body["occurrences"].first
    expect(item).to include("id" => occurrence.id, "host" => { "id" => occurrence.host_id, "hostname" => "web-1" })
    expect(item.fetch("normalized_denial")).to include("status" => "ok", "source_type" => "httpd_t", "target_class" => "file", "permissions" => ["read"])
    expect(item.fetch("raw_event")).to include(
      "id" => occurrence.raw_event_id, "audit_sequence" => 1, "evidence_digest" => "raw-digest",
         "audit_records" => [include("record_type" => 1400, "payload" => item.dig("raw_event", "audit_records", 0, "payload"))]
    )
    expect(item.dig("raw_event", "audit_records", 0, "payload")).to include("type=AVC")
    expect(item.fetch("guidance")).to include("summary", "observations", "checks", "missing_evidence", "historical_limitations")
    expect(body.fetch("meta")).to include("next_cursor" => nil)
  end

  it "serves scoped port inspection commands on both occurrence detail routes" do
    issue = create_issue(target_type: "unreserved_port_t", target_class: "tcp_socket", permissions: ["name_bind"])
    occurrence = create_occurrence(issue)
    occurrence.normalized_denial.update!(target_class: issue.target_class, permissions: issue.permissions,
      details: { "network_evidence" => { "bind_port_fields" => ["12345"] } })

    ["/api/v1/issues/#{issue.id}/occurrences/#{occurrence.id}", "/api/v1/hosts/#{occurrence.host_id}/occurrences/#{occurrence.id}"].each do |path|
      get path
      expect(response).to have_http_status(:ok)
      checks = JSON.parse(response.body).fetch("guidance").fetch("checks")
      expect(checks).to include(include("kind" => "port_classification", "command" => "semanage port -l", "target" => "tcp/12345"))
      expect(checks).to include(include("kind" => "port_local_classification", "command" => "semanage port -l -C", "target" => "tcp/12345"))
      listener = checks.find { |item| item["kind"] == "socket_listeners" }
      expect(Shellwords.split(listener.fetch("command"))).to eq(["ss", "-ltnp", "sport = :12345"])
      expect(checks).to include(include("kind" => "port_policy_alternatives", "command" => "sesearch -A -s httpd_t -c tcp_socket -p name_bind"))
      shared = checks.select { |check| check["command"] }.map { |check| { title: check["reason"], command: check["command"], interpretation: check["expected"] } }
      expect(IssueOperatorGuidance.call(issue, occurrence: occurrence)[:checks]).to eq(shared)
    end
  end

  it "returns historical checkpoint and receipt provenance rather than the host's current inventory" do
    issue = create_issue
    occurrence = create_occurrence(issue)
    occurrence.host_snapshot.update!(details: { "platform" => { "kernel_release" => "historical-kernel" } })
    latest = HostSnapshot.create!(host: occurrence.host, details: { "platform" => { "kernel_release" => "latest-kernel" } })
    occurrence.host.host_snapshot_observations.create!(agent_installation: occurrence.raw_event.agent_installation, host_snapshot: latest,
      first_observed_at: Time.current, last_observed_at: Time.current, first_received_at: Time.current, last_received_at: Time.current)
    get "/api/v1/issues/#{issue.id}/occurrences/#{occurrence.id}"
    body = JSON.parse(response.body).fetch("raw_event")
    expect(body.fetch("checkpoint")).to include("snapshot_id" => occurrence.host_snapshot_id, "kernel_release" => "historical-kernel", "observed_at" => occurrence.raw_event.host_observed_at.iso8601(3))
    expect(body.fetch("collection")).to include("agent_installation_id" => occurrence.raw_event.agent_installation_id, "schema_version" => 2,
      "agent_received_at" => occurrence.raw_event.agent_received_at.iso8601(3), "server_received_at" => occurrence.raw_event.server_received_at.iso8601(3))
    occurrence.update!(host_snapshot: nil)
    get "/api/v1/issues/#{issue.id}/occurrences/#{occurrence.id}"
    expect(JSON.parse(response.body).dig("raw_event", "checkpoint")).to include("snapshot_id" => nil, "kernel_release" => nil)
  end

  it "preserves network destinations independently of policy findings and scopes mixed checkpoint coverage" do
    issue = create_issue(target_type: "unreserved_port_t", target_class: "tcp_socket", permissions: ["name_connect"])
    stale = create_occurrence(issue, "network-stale", 1)
    first = create_occurrence(issue, "network-first", 2, host: stale.host)
    second = create_occurrence(issue, "network-second", 3, host: stale.host)
    [stale, first, second].each_with_index do |occurrence, index|
      configure_policy_occurrence(occurrence, result: "matched", identity: "sha256:network", boolean: index.zero?)
      details = occurrence.normalized_denial.details.deep_merge("network_evidence" => { "dest_fields" => [index == 1 ? "12346" : "12345"], "dport_fields" => [] })
      occurrence.normalized_denial.update!(command: "httpd", executable: "/usr/sbin/httpd", details: details)
    end
    get "/api/v1/issues/#{issue.id}"
    body = JSON.parse(response.body)
    expect(body.dig("finding_coverage", "conditional_allow_inactive")).to eq(2)
    expect(body.dig("finding_coverage", "unexplained")).to eq(1)
    expect(body.dig("policy_analysis", "limitations").join).to include("1 denial", "active at the associated checkpoint", "not an AVC-time")
    expect(body.dig("intelligence", "resource_summary")).to include("destination_port_count" => 2, "destination_ports" => [{ "port" => "12345", "occurrence_count" => 2 }, { "port" => "12346", "occurrence_count" => 1 }])
    expect(body.dig("findings", 0, "occurrence_count")).to eq(1)
    expect(body.fetch("additional_finding_count")).to eq(1)

    queries = []
    subscription = ActiveSupport::Notifications.subscribe("sql.active_record") { |event| queries << event.payload[:sql] }
    get "/api/v1/issues/#{issue.id}/occurrences", params: { view: "summary" }
    ActiveSupport::Notifications.unsubscribe(subscription)
    summaries = JSON.parse(response.body).fetch("occurrences")
    expect(summaries.map { |item| item["resource"] }).to eq(["TCP/12345", "TCP/12346", "TCP/12345"])
    expect(queries.none? { |sql| sql.include?('FROM "raw_audit_records"') || sql.include?('FROM "raw_events"') }).to be(true)
    expect(IssueIntelligence.destination_ports({ "network_evidence" => { "dest_fields" => ["127.0.0.1", "example.test", "12345", "12345"] } })).to eq(["12345"])
  end

  it "summarizes bind endpoints across all occurrences independently of findings and pagination" do
    issue = create_issue(target_type: "unreserved_port_t", target_class: "tcp_socket", permissions: ["name_bind"])
    ["12345", "23451", "23451", nil, "99999"].each_with_index do |port, index|
      occurrence = create_occurrence(issue, "bind-summary-#{index}", index + 1)
      occurrence.normalized_denial.update!(target_class: issue.target_class, permissions: issue.permissions,
        details: { "network_evidence" => { "bind_port_fields" => [port].compact } })
    end
    get "/api/v1/issues/#{issue.id}"
    expect(JSON.parse(response.body).dig("intelligence", "resource_summary")).to include(
      "bind_port_count" => 2, "without_bind_port_occurrences" => 2,
      "bind_ports" => [{ "port" => "23451", "occurrence_count" => 2 }, { "port" => "12345", "occurrence_count" => 1 }])
    get "/api/v1/issues/#{issue.id}/occurrences", params: { view: "summary", limit: 2, page: 2 }
    body = JSON.parse(response.body)
    expect(body.fetch("meta")).to include("total" => 5, "page" => 2)
    expect(body.fetch("occurrences").map { |item| item["resource"] }).to eq(["TCP/23451", "TCP/23451"])
  end

  it "composes conditional-read and file-context findings, then retains policy knowledge when the path is unavailable" do
    issue = create_issue(target_type: "user_home_t")
    occurrence = create_occurrence(issue)
    identity = "sha256:" + "c" * 64
    rule = "allow httpd_t user_home_type:file { getattr ioctl lock open read }; [ httpd_read_user_content ]:True"
    occurrence.host_snapshot.update!(details: { "selinux" => { "policy_identity" => identity, "booleans" => [{ "name" => "httpd_read_user_content", "current" => false, "status" => "observed" }] } })
    occurrence.normalized_denial.update!(target_type: "user_home_t", target_context: "unconfined_u:object_r:user_home_t:s0", command: "httpd", executable: "/usr/sbin/httpd", details: { "target_evidence" => { "filesystem_paths" => ["/var/www/html/secentral-test.html"], "object_names" => ["secentral-test.html"] }, "enforcement_mode" => "enforcing", "syscall_evidence" => [{ "syscall" => "257", "success" => "no", "exit" => "-13" }] })
    PolicyFact.create!(policy_identity: identity, query_kind: "allow", source_type: "httpd_t", target_type: "user_home_t", object_class: "file", permission: "read", status: "matched", matching_rules: [rule], evaluator_version: "4.5.1", evaluated_at: Time.current)
    occurrence.raw_event.update!(file_context_observations: [{ "kind" => "expected_context", "path" => "/var/www/html/secentral-test.html", "object_class" => "file", "file_type" => "file", "status" => "resolved", "expected_context" => "system_u:object_r:httpd_sys_content_t:s0", "observed_at" => Time.current.iso8601(6), "resolver" => "matchpathcon" }])
    get "/api/v1/issues/#{issue.id}"
    body = JSON.parse(response.body)
    expect(body.fetch("findings").map { |item| item.dig("diagnosis", "kind") }).to eq(%w[file_context_mismatch conditional_allow_inactive])
    expect(body.fetch("findings")).to all(include("occurrence_count" => 1))
    expect(body.fetch("finding_coverage")).to include("file_context_mismatch" => 1, "conditional_allow_inactive" => 1)
    expect(body.dig("findings", 0, "observation_count")).to eq(1)
    expect(body.dig("findings", 0, "reused_observation_occurrences")).to eq(0)
    expect(body.dig("findings", 1, "diagnosis")).to include("operation" => "read", "policy_identity" => identity, "checkpoint_observed_at" => occurrence.raw_event.host_observed_at.iso8601(3))
    expect(body.dig("findings", 1, "diagnosis", "conditional_rules", 0, "rule")).to eq(rule)
    expect(body.dig("findings", 1, "diagnosis", "evidence").to_json).not_to include("execve")
    scoped_findings = body.fetch("host_explanations").sole.fetch("diagnosis_groups").sole.fetch("findings")
    expect(scoped_findings.map { |finding| finding["kind"] }).to eq(%w[file_context_mismatch conditional_allow_inactive])
    expect(scoped_findings).to all(include("occurrence_id" => occurrence.id, "host_id" => occurrence.host_id))
    expect(body.fetch("host_explanations").sole.fetch("diagnosis_groups").sole).to include("policy_identity_count" => 1,
      "policy_provenance" => [include("policy_identity" => identity, "occurrence_id" => occurrence.id)])

    repeated = create_occurrence(issue, "read-repeat", 2, host: occurrence.host)
    repeated.update!(host_snapshot: occurrence.host_snapshot)
    repeated.raw_event.update!(host_snapshot: occurrence.host_snapshot, boot_id: occurrence.raw_event.boot_id, host_observed_at: occurrence.raw_event.host_observed_at)
    repeated.normalized_denial.update!(occurrence.normalized_denial.attributes.slice("target_type", "target_context", "command", "executable", "details"))
    get "/api/v1/issues/#{issue.id}"
    body = JSON.parse(response.body)
    expect(body.dig("findings", 0, "occurrence_count")).to eq(2)
    expect(body.dig("findings", 0, "observation_count")).to eq(1)
    expect(body.dig("findings", 0, "reused_observation_occurrences")).to eq(1)
    repeated.raw_event.update!(host_observed_at: occurrence.raw_event.host_observed_at + 1.minute)
    get "/api/v1/issues/#{issue.id}"
    body = JSON.parse(response.body)
    expect(body.fetch("finding_coverage")).to include("file_context_mismatch" => 1, "conditional_allow_inactive" => 2)

    occurrence.normalized_denial.update!(details: occurrence.normalized_denial.details.deep_merge("target_evidence" => { "filesystem_paths" => [] }))
    repeated.normalized_denial.update!(details: repeated.normalized_denial.details.deep_merge("target_evidence" => { "filesystem_paths" => [] }))
    occurrence.raw_event.update!(file_context_observations: [])
    get "/api/v1/issues/#{issue.id}"
    body = JSON.parse(response.body)
    expect(body.dig("diagnosis", "kind")).to eq("conditional_allow_inactive")
    expect(body.dig("diagnosis", "path")).to be_nil
    expect(body.dig("intelligence", "resource_summary", "without_absolute_path_occurrences")).to eq(2)
    expect(body.fetch("finding_coverage")).to eq("conditional_allow_inactive" => 2)
  end

  it "pages occurrences with a stable cursor across identical timestamps" do
    issue = create_issue
    timestamp = Time.utc(2026, 9, 13, 12, 0, 0)
    a = create_occurrence(issue, "cursor-a", 1, occurred_at: timestamp)
    b = create_occurrence(issue, "cursor-b", 2, occurred_at: timestamp)
    c = create_occurrence(issue, "cursor-c", 3, occurred_at: timestamp)

    get "/api/v1/issues/#{issue.id}/occurrences", params: { limit: 2 }
    body = JSON.parse(response.body)
    expect(body["occurrences"].map { |item| item["id"] }).to eq([c.id, b.id])
    cursor = body.dig("meta", "next_cursor")
    expect(cursor).to be_a(String)

    get "/api/v1/issues/#{issue.id}/occurrences", params: { limit: 2, before: cursor }
    body = JSON.parse(response.body)
    expect(body["occurrences"].map { |item| item["id"] }).to eq([a.id])
    expect(body.dig("meta", "next_cursor")).to be_nil

    get "/api/v1/issues/#{issue.id}/occurrences", params: { before: "not-a-cursor" }
    expect(response).to have_http_status(:unprocessable_content)
  end

  it "pages lightweight occurrence summaries without reading raw records and scopes selected evidence to the issue" do
    issue = create_issue
    host = Host.create!(organization: issue.organization, external_id: "summary-host", hostname: "web-1")
    26.times { |index| create_occurrence(issue, "summary-#{index}", index + 1, host: host) }
    occurrence = issue.occurrences.order(id: :desc).first
    occurrence.normalized_denial.update!(details: { "target_evidence" => { "object_names" => ["secentral-test.html"], "filesystem_paths" => [] } })
    queries = []
    subscriber = ActiveSupport::Notifications.subscribe("sql.active_record") { |event| queries << event.payload[:sql] }
    get "/api/v1/issues/#{issue.id}/occurrences", params: { view: "summary", page: 1 }
    ActiveSupport::Notifications.unsubscribe(subscriber)
    body = JSON.parse(response.body)
    expect(body.fetch("occurrences").size).to eq(10)
    expect(body.fetch("meta")).to include("page" => 1, "page_size" => 10, "total" => 26, "total_pages" => 3)
    expect(body.fetch("occurrences").flat_map(&:keys)).not_to include("raw_event", "normalized_denial", "guidance")
    expect(queries.none? { |sql| sql.include?('FROM "raw_audit_records"') || sql.include?('FROM "raw_events"') }).to be(true)
    first_ids = body.fetch("occurrences").map { |item| item["id"] }
    get "/api/v1/issues/#{issue.id}/occurrences", params: { view: "summary", page: 2 }
    second_ids = JSON.parse(response.body).fetch("occurrences").map { |item| item["id"] }
    expect(second_ids.size).to eq(10)
    expect(first_ids & second_ids).to be_empty
    get "/api/v1/issues/#{issue.id}/occurrences/#{occurrence.id}"
    expect(JSON.parse(response.body).fetch("id")).to eq(occurrence.id)
    expect(JSON.parse(response.body).dig("raw_event", "file_context_observations")).to eq([])
    other = create_issue("other-detail")
    get "/api/v1/issues/#{other.id}/occurrences/#{occurrence.id}"
    expect(response).to have_http_status(:not_found)
  end

  it "bounds resource examples and reports path coverage rather than serializing every basename" do
    issue = create_issue
    5.times do |index|
      occurrence = create_occurrence(issue, "bounded-#{index}", index + 1)
      occurrence.normalized_denial.update!(details: { "target_evidence" => { "object_names" => ["#{index}.txt"], "filesystem_paths" => [] } })
    end
    get "/api/v1/issues/#{issue.id}"
    summary = JSON.parse(response.body).fetch("intelligence")
    expect(summary.fetch("names").size).to eq(3)
    expect(summary.fetch("resource_summary")).to include("name_count" => 5, "without_absolute_path_occurrences" => 5, "absolute_path_occurrences" => 0)
  end

  it "bounds occurrence pages and walks the full history through cursors" do
    issue = create_issue
    101.times { |index| create_occurrence(issue, "host-#{index + 1}", index + 1) }

    get "/api/v1/issues/#{issue.id}/occurrences"
    body = JSON.parse(response.body)
    expect(body["occurrences"].length).to eq(50)
    cursor = body.dig("meta", "next_cursor")
    expect(cursor).to be_a(String)

    get "/api/v1/issues/#{issue.id}/occurrences", params: { before: cursor }
    body = JSON.parse(response.body)
    expect(body["occurrences"].length).to eq(50)
    cursor = body.dig("meta", "next_cursor")

    get "/api/v1/issues/#{issue.id}/occurrences", params: { before: cursor }
    body = JSON.parse(response.body)
    expect(body["occurrences"].length).to eq(1)
    expect(body.dig("meta", "next_cursor")).to be_nil
  end

  it "exposes the analysis sections on the analysis subresource" do
    issue = create_issue(target_type: "unreserved_port_t", target_class: "tcp_socket", permissions: ["name_connect"])
    conditional = create_occurrence(issue, "host-a", 1)
    no_match = create_occurrence(issue, "host-b", 2)
    [conditional, no_match].each { |occurrence| occurrence.normalized_denial.update!(command: "httpd", executable: "/usr/sbin/httpd") }
    configure_policy_occurrence(conditional, result: "matched", identity: "sha256:host-a", boolean: false)
    configure_policy_occurrence(no_match, result: "no_match", identity: "sha256:host-b")

    get "/api/v1/issues/#{issue.id}"

    detail = JSON.parse(response.body)
    primary = detail.fetch("diagnosis")
    primary_occurrence = [ conditional, no_match ].find { |occurrence| occurrence.id == primary.fetch("occurrence_id") }
    expect(primary).to include(
      "policy_identity" => primary_occurrence.host_snapshot.details.dig("selinux", "policy_identity"),
      "checkpoint_observed_at" => primary_occurrence.raw_event.host_observed_at.iso8601(3),
      "process_command" => "httpd",
      "executable" => "/usr/sbin/httpd"
    )
    expect(detail.fetch("fleet_explanation")).to include("state" => "disagreement", "affected_host_count" => 2)
    host_a = detail.fetch("host_explanations").find { |host| host["host_id"] == conditional.host_id }
    host_b = detail.fetch("host_explanations").find { |host| host["host_id"] == no_match.host_id }
    expect(host_a.dig("diagnosis_groups", 0, "diagnosis", "kind")).to eq("conditional_allow_inactive")
    expect(host_b.dig("diagnosis_groups", 0, "diagnosis", "kind")).to eq("no_matching_allow")
    expect(host_a.dig("diagnosis_groups", 0)).not_to have_key("agreement_signature")

    get "/api/v1/issues/#{issue.id}/analysis"

    body = JSON.parse(response.body)
    expect(response).to have_http_status(:ok)
    host_a = body["host_explanations"].find { |item| item["host_id"] == conditional.host_id }
    host_b = body["host_explanations"].find { |item| item["host_id"] == no_match.host_id }
    expect(host_a).to include("status" => "agreement", "diagnosis" => include("kind" => "conditional_allow_inactive"))
    expect(host_a.fetch("occurrence_diagnoses")).to contain_exactly(include("occurrence_id" => conditional.id, "diagnosis" => include("kind" => "conditional_allow_inactive")))
    expect(host_b).to include("status" => "agreement", "diagnosis" => include("kind" => "no_matching_allow"))
    expect(host_b.fetch("occurrence_diagnoses")).to contain_exactly(include("occurrence_id" => no_match.id, "diagnosis" => include("kind" => "no_matching_allow")))
    expect(body.fetch("fleet_explanation")).to include("state", "affected_host_count", "explanation_groups")
    expect(body.fetch("hypotheses").first).to include("kind", "label", "confidence_band", "supporting_evidence", "missing_evidence")
    expect(body.fetch("supporting_evidence")).to have_key("explanation")
    expect(body.fetch("supporting_evidence")).to have_key("file_contexts")
  end

  it "does not select a host explanation when its occurrences disagree" do
    issue = create_issue(target_type: "unreserved_port_t", target_class: "tcp_socket", permissions: ["name_connect"])
    conditional = create_occurrence(issue, "host-a", 1)
    no_match = create_occurrence(issue, "host-a", 2, host: conditional.host)
    configure_policy_occurrence(conditional, result: "matched", identity: "sha256:host-a", boolean: false)
    configure_policy_occurrence(no_match, result: "no_match", identity: "sha256:host-a-new")

    get "/api/v1/issues/#{issue.id}/analysis"

    host = JSON.parse(response.body).dig("host_explanations").first
    expect(host).to include("status" => "disagreement", "diagnosis" => nil)
    expect(host.fetch("occurrence_diagnoses")).to include(include("diagnosis" => include("kind" => "conditional_allow_inactive")), include("diagnosis" => include("kind" => "no_matching_allow")))
  end

  it "reuses one conditional fact while evaluating each occurrence checkpoint separately" do
    issue = create_issue(target_type: "unreserved_port_t", target_class: "tcp_socket", permissions: ["name_connect"])
    first = create_occurrence(issue, "host-a", 1)
    different_boolean = create_occurrence(issue, "host-a", 2, host: first.host)
    configure_policy_occurrence(first, result: "matched", identity: "sha256:policy", boolean: false)
    configure_policy_occurrence(different_boolean, result: "matched", identity: "sha256:policy", boolean: true)
    expect(host_explanation(issue)).to include("status" => "insufficient_evidence")

    equivalent = issue
    first = create_occurrence(equivalent, "host-b", 1)
    second = create_occurrence(equivalent, "host-b", 2, host: first.host)
    configure_policy_occurrence(first, result: "matched", identity: "sha256:policy", boolean: false, fact_extra: { "captured_at" => "old" })
    configure_policy_occurrence(second, result: "matched", identity: "sha256:policy", boolean: false, fact_extra: { "captured_at" => "new" })
    result = host_explanation(equivalent)
    expect(result).to include("status" => "agreement")
    expect(result.fetch("occurrence_diagnoses").map { |item| item.fetch("agreement_signature") }.uniq.size).to eq(1)

    configure_policy_occurrence(second, result: "matched", identity: "sha256:policy", boolean: false, fact_extra: { "provenance" => "different-loaded-policy-source" })
    expect(host_explanation(equivalent)).to include("status" => "agreement")
  end

  it "agrees on equivalent connect conclusions across policy identities and evaluator versions but preserves active checkpoint differences" do
    issue = create_issue(target_type: "unreserved_port_t", target_class: "tcp_socket", permissions: ["name_connect"])
    first = create_occurrence(issue, "connect-host-a", 1)
    second = create_occurrence(issue, "connect-host-b", 2)
    configure_policy_occurrence(first, result: "matched", identity: "sha256:connect-a", boolean: false)
    configure_policy_occurrence(second, result: "matched", identity: "sha256:connect-b", boolean: false)
    PolicyFact.find_by!(policy_identity: second.host_snapshot.details.dig("selinux", "policy_identity")).update!(evaluator_version: "another-version")
    get "/api/v1/issues/#{issue.id}/analysis"
    body = JSON.parse(response.body)
    expect(body.dig("fleet_explanation", "state")).to eq("consistent")
    expect(body.fetch("host_explanations")).to all(include("status" => "agreement"))
    configure_policy_occurrence(second, result: "matched", identity: "sha256:connect-b", boolean: true)
    get "/api/v1/issues/#{issue.id}/analysis"
    body = JSON.parse(response.body)
    expect(body.dig("fleet_explanation", "state")).to eq("partially_explained")
    expect(body.fetch("host_explanations").find { |host| host["host_id"] == second.host_id }).to include("status" => "insufficient_evidence", "diagnosis" => nil)
  end

  it "keeps identical no-match conclusions in agreement across different policy identities" do
    issue = create_issue(target_type: "unreserved_port_t", target_class: "tcp_socket", permissions: ["name_connect"])
    first = create_occurrence(issue, "host-a", 1)
    second = create_occurrence(issue, "host-a", 2, host: first.host)
    configure_policy_occurrence(first, result: "no_match", identity: "sha256:old")
    configure_policy_occurrence(second, result: "no_match", identity: "sha256:new")
    result = host_explanation(issue)
    expect(result).to include("status" => "agreement")
    expect(result.fetch("occurrence_diagnoses").map { |item| item.dig("diagnosis", "policy_identity") }.uniq.size).to eq(2)
    expect(result.fetch("occurrence_diagnoses").map { |item| item.fetch("agreement_signature") }.uniq.size).to eq(1)

    get "/api/v1/issues/#{issue.id}"
    host = JSON.parse(response.body).dig("host_explanations").first
    group = host.fetch("diagnosis_groups").first
    expect(host).to include("status" => "agreement", "occurrence_count" => 2)
    expect(group).to include("count" => 2, "policy_identity_count" => 2)
    expect(group.fetch("policy_provenance").map { |item| item.fetch("policy_identity") }.uniq.size).to eq(2)
    expect(JSON.parse(response.body).dig("fleet_explanation", "state")).to eq("consistent")

    equivalent = issue
    first = create_occurrence(equivalent, "host-b", 1)
    second = create_occurrence(equivalent, "host-b", 2, host: first.host)
    configure_policy_occurrence(first, result: "no_match", identity: "sha256:policy", fact_extra: { "captured_at" => "old" })
    configure_policy_occurrence(second, result: "no_match", identity: "sha256:policy", fact_extra: { "captured_at" => "new" })
    expect(host_explanation(equivalent)).to include("status" => "agreement")
  end

  it "keeps port-specific no-match findings scoped to their own occurrences" do
    issue = create_issue(target_type: "unreserved_port_t", target_class: "tcp_socket", permissions: ["name_connect"])
    first = create_occurrence(issue, "host-a", 1)
    second = create_occurrence(issue, "host-a", 2, host: first.host)
    [first, second].each { |occurrence| configure_policy_occurrence(occurrence, result: "no_match", identity: "sha256:policy") }
    details = second.normalized_denial.details.deep_dup
    details["network_evidence"]["dport_fields"] = ["9090"]
    second.normalized_denial.update!(details: details)

    get "/api/v1/issues/#{issue.id}"

    body = JSON.parse(response.body)
    expect(body.fetch("findings").sole.fetch("occurrence_count")).to eq(1)
    expect(body.fetch("additional_finding_count")).to eq(1)
    groups = body.fetch("host_explanations").sole.fetch("diagnosis_groups")
    expect(groups.map { |group| group.dig("diagnosis", "destination_port") }).to contain_exactly("12345", "9090")
    expect(groups.map { |group| group.fetch("count") }).to eq([1, 1])
    groups.each do |group|
      diagnosis = group.fetch("diagnosis")
      expect(diagnosis.fetch("title")).to include("connecting to TCP port #{diagnosis.fetch('destination_port')}")
    end
  end

  it "compares file-context types and preserves insufficient per-occurrence evidence" do
    issue = create_issue(target_type: "var_t")
    first = create_occurrence(issue, "host-a", 1)
    second = create_occurrence(issue, "host-a", 2, host: first.host)
    configure_file_context_occurrence(first, context: "system_u:object_r:var_t:s0", expected_context: "system_u:object_r:custom_t:s0")
    configure_file_context_occurrence(second, context: "system_u:object_r:var_t:s0:c0", expected_context: "system_u:object_r:custom_t:s0")
    expect(host_explanation(issue)).to include("status" => "agreement")

    equivalent = issue
    first = create_occurrence(equivalent, "host-b", 1)
    second = create_occurrence(equivalent, "host-b", 2, host: first.host)
    configure_file_context_occurrence(first, context: "system_u:object_r:var_t:s0", expected_context: "system_u:object_r:custom_t:s0", enforcement: "enforcing")
    configure_file_context_occurrence(second, context: "system_u:object_r:var_t:s0", expected_context: "system_u:object_r:custom_t:s0", enforcement: "permissive")
    expect(host_explanation(equivalent)).to include("status" => "agreement")

    insufficient = create_occurrence(equivalent, "host-b", 3, host: first.host)
    expect(host_explanation(equivalent)).to include("status" => "insufficient_evidence")
  end

  it "returns not found for an unknown issue on every detail endpoint" do
    get "/api/v1/issues/999999"
    expect(response).to have_http_status(:not_found)
    expect(JSON.parse(response.body)).to include("error" => hash_including("code" => "not_found"))

    get "/api/v1/issues/999999/occurrences"
    expect(response).to have_http_status(:not_found)

    get "/api/v1/issues/999999/analysis"
    expect(response).to have_http_status(:not_found)

    token = csrf_token
    patch "/api/v1/issues/999999/status", params: { status: "resolved" }.to_json, headers: json_headers(token)
    expect(response).to have_http_status(:not_found)

    patch "/api/v1/issues/999999/disposition", params: { disposition: "expected_harmless" }.to_json, headers: json_headers(token)
    expect(response).to have_http_status(:not_found)
  end

  it "rejects detail subresources unauthenticated" do
    sign_in_operator
    sign_out_operator

    get "/api/v1/issues/1"
    expect(response).to have_http_status(:unauthorized)
    get "/api/v1/issues/1/occurrences"
    expect(response).to have_http_status(:unauthorized)
    get "/api/v1/issues/1/analysis"
    expect(response).to have_http_status(:unauthorized)
    patch "/api/v1/issues/1/status", params: { status: "resolved" }.to_json, headers: { "Content-Type" => "application/json" }
    expect(response).to have_http_status(:unauthorized)
    patch "/api/v1/issues/1/disposition", params: { disposition: "expected_harmless" }.to_json, headers: { "Content-Type" => "application/json" }
    expect(response).to have_http_status(:unauthorized)
  end

  it "transitions issue status and returns the refreshed core" do
    issue = create_issue

    token = csrf_token
    patch "/api/v1/issues/#{issue.id}/status", params: { status: "resolved", signature_ids: issue.signatures.ids }.to_json, headers: json_headers(token)

    expect(response).to have_http_status(:ok)
    body = JSON.parse(response.body)
    expect(body).to include("id" => issue.id, "status" => "resolved")
    expect(body).to have_key("resolved_at")
    expect(issue.reload).to have_attributes(status: "resolved")
    expect(issue.resolved_at).not_to be_nil

    get "/api/v1/issues/#{issue.id}"
    expect(JSON.parse(response.body).dig("issue", "status")).to eq("resolved")

    token = csrf_token
    patch "/api/v1/issues/#{issue.id}/status", params: { status: "bogus", signature_ids: issue.signatures.ids }.to_json, headers: json_headers(token)
    expect(response).to have_http_status(:unprocessable_content)
    expect(JSON.parse(response.body)).to include("error" => hash_including("code" => "invalid_value"))
  end

  it "records operator disposition with a note and history" do
    issue = create_issue

    token = csrf_token
    patch "/api/v1/issues/#{issue.id}/disposition", params: { disposition: "expected_harmless", note: "Known baseline behavior", signature_ids: issue.signatures.ids }.to_json, headers: json_headers(token)

    expect(response).to have_http_status(:ok)
    body = JSON.parse(response.body)
    expect(body).to include("id" => issue.id, "disposition" => "expected_harmless", "status" => "open")
    expect(body.dig("disposition_history", 0)).to include("disposition" => "expected_harmless", "previous_disposition" => "unclassified", "note" => "Known baseline behavior")

    token = csrf_token
    patch "/api/v1/issues/#{issue.id}/disposition", params: { disposition: "automatically_fixed", signature_ids: issue.signatures.ids }.to_json, headers: json_headers(token)
    expect(response).to have_http_status(:unprocessable_content)
    expect(issue.reload.disposition).to eq("expected_harmless")
  end

  it "rejects implicit review scope and signatures outside the issue without partial updates" do
    issue = create_issue
    other = create_issue
    token = csrf_token
    patch "/api/v1/issues/#{issue.id}/status", params: { status: "ignored" }.to_json, headers: json_headers(token)
    expect(response).to have_http_status(:bad_request)
    patch "/api/v1/issues/#{issue.id}/status", params: { status: "ignored", signature_ids: issue.signatures.ids + other.signatures.ids }.to_json, headers: json_headers(token)
    expect(response).to have_http_status(:unprocessable_content)
    expect(issue.signatures.reload.map(&:status)).to eq(["open"])
    patch "/api/v1/issues/#{issue.id}/disposition", params: { disposition: "expected_harmless", signature_ids: other.signatures.ids }.to_json, headers: json_headers(token)
    expect(response).to have_http_status(:unprocessable_content)
    expect(issue.reload.disposition).to eq("unclassified")
    expect(IssueDispositionChange.count).to eq(0)
  end

  it "applies the submitted review snapshot without hiding signatures received since the page was read" do
    issue = create_issue
    reviewed = issue.signatures.ids
    issue.signatures.create!(fingerprint_version: 3, fingerprint_digest: "new-execute", permissions: ["execute"],
      first_seen_at: Time.current, last_seen_at: Time.current)
    token = csrf_token
    patch "/api/v1/issues/#{issue.id}/status", params: { status: "ignored", signature_ids: reviewed }.to_json, headers: json_headers(token)
    expect(response).to have_http_status(:ok)
    expect(issue.reload.status).to eq("open")
    expect(issue.signatures.find(reviewed.sole).status).to eq("ignored")
    expect(issue.signatures.order(:id).last.status).to eq("open")
  end

  it "filters signature occurrences and retains exact permissions, mode and syscall outcome" do
    issue = create_issue
    occurrence = create_occurrence(issue)
    occurrence.normalized_denial.update!(details: { "enforcement_mode" => "permissive", "syscall_evidence" => [{ "success" => "yes" }] })
    signature = issue.signatures.create!(fingerprint_version: 3, fingerprint_digest: "map", permissions: ["map"],
      first_seen_at: Time.current, last_seen_at: Time.current)
    another = create_occurrence(issue, "host-2", 2)
    another.update!(issue_signature: signature)
    another.normalized_denial.update!(permissions: ["map"])
    get "/api/v1/issues/#{issue.id}/occurrences", params: { view: "summary", signature_id: occurrence.issue_signature_id }
    body = JSON.parse(response.body)
    expect(body.dig("meta", "total")).to eq(1)
    expect(body.fetch("occurrences").sole).to include("id" => occurrence.id, "permissions" => ["read"], "enforcement_mode" => "permissive", "syscall_outcome" => "succeeded")
    foreign = create_issue
    get "/api/v1/issues/#{issue.id}/occurrences", params: { view: "summary", signature_id: foreign.signatures.first.id }
    expect(response).to have_http_status(:not_found)
  end

  %w[enforcing permissive].each do |rich_mode|
    it "leads with a retained path on a #{rich_mode} host instead of a basename-only Boolean example" do
      issue = create_issue(target_type: "user_home_t", permissions: %w[open read map])
      basename = create_occurrence(issue, "host-basename")
      richer = create_occurrence(issue, "host-path", 2)
      basename.update!(occurred_at: richer.occurred_at + 10.seconds)
      basename.normalized_denial.update!(target_type: "user_home_t", target_context: "system_u:object_r:user_home_t:s0", details: {
        "enforcement_mode" => rich_mode == "permissive" ? "enforcing" : "permissive",
        "target_evidence" => { "filesystem_paths" => [], "object_names" => ["page.html"] }
      })
      identity = "sha256:#{'1' * 64}"
      basename.host_snapshot.update!(details: { "selinux" => { "policy_identity" => identity,
        "booleans" => [{ "name" => "httpd_read_user_content", "status" => "observed", "current" => false }] } })
      PolicyFact.create!(policy_identity: identity, query_kind: "allow", source_type: "httpd_t", target_type: "user_home_t", object_class: "file",
        permission: "read", status: "matched", matching_rules: ["allow httpd_t user_home_t:file read; [ httpd_read_user_content ]:True"])
      richer.normalized_denial.update!(target_type: "user_home_t", target_context: "system_u:object_r:user_home_t:s0", permissions: %w[open read], details: {
        "enforcement_mode" => rich_mode, "target_evidence" => { "filesystem_paths" => ["/var/www/html/page.html"] }
      })

      get "/api/v1/issues/#{issue.id}"
      expect(response).to have_http_status(:ok)
      body = JSON.parse(response.body)
      expect(body.dig("diagnosis", "kind")).to eq("conditional_allow_inactive")
      expect(body["triage_guidance"]).to include("path" => "/var/www/html/page.html", "host_id" => richer.host_id, "occurrence_id" => richer.id)
      expect(body.dig("operator_guidance", "source")).to include("host_id" => richer.host_id, "occurrence_id" => richer.id, "path" => "/var/www/html/page.html")
      expect(body.dig("operator_guidance", "checks").map { |check| check["command"] }).to include("matchpathcon -- /var/www/html/page.html", "restorecon -n -v -- /var/www/html/page.html")
      expect(body.dig("operator_guidance", "checks").map { |check| check["command"] }).not_to include("getsebool httpd_read_user_content")
      expect(issue.occurrences.count).to eq(2)
    end
  end

  it "does not borrow another host's configured context to suppress the selected path's labeling lead" do
    issue = create_issue(target_type: "user_home_t")
    first = create_occurrence(issue, "host-agreement")
    configure_file_context_occurrence(first, context: "system_u:object_r:user_home_t:s0", expected_context: "system_u:object_r:user_home_t:s0")
    second = create_occurrence(issue, "host-uninspected", 2)
    second.normalized_denial.update!(target_type: "user_home_t", target_context: "system_u:object_r:user_home_t:s0", details: { "target_evidence" => { "filesystem_paths" => ["/srv/app/data"] } })
    get "/api/v1/issues/#{issue.id}"
    body = JSON.parse(response.body)
    expect(body.dig("operator_guidance", "source", "host_id")).to eq(second.host_id)
    expect(body["triage_guidance"]).to include("host_id" => second.host_id, "path" => "/srv/app/data")
    second.raw_event.update!(file_context_observations: first.raw_event.file_context_observations)
    get "/api/v1/issues/#{issue.id}"
    expect(JSON.parse(response.body)["triage_guidance"]).to be_nil
  end

  it "returns page-local activity groups without changing retained events or summary evidence loading" do
    issue = create_issue
    first = create_occurrence(issue)
    second = create_occurrence(issue, "host-1", 2, host: first.host, occurred_at: first.occurred_at + 0.001)
    [first, second].each_with_index do |item, index|
      permissions = index.zero? ? %w[open read] : ["map"]
      item.normalized_denial.update!(permissions: permissions, details: { "enforcement_mode" => "permissive",
        "target_evidence" => { "filesystem_paths" => ["/var/www/html/page.html"] } })
      item.raw_event.raw_audit_records.create!(position: 0, record_type: 1400, type_name: "AVC", audit_timestamp: item.occurred_at, sequence: index + 1,
        payload: "avc: denied { #{permissions.join(' ')} } for pid=42 dev=vda1 ino=123 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:default_t:s0 tclass=file permissive=1")
    end
    get "/api/v1/issues/#{issue.id}/occurrences", params: { view: "activity" }
    body = JSON.parse(response.body)
    expect(body).to include("activity_scope" => "current_page")
    expect(body.fetch("activity_groups").sole).to include("occurrence_ids" => [first.id, second.id], "correlated" => true)
    expect(body.dig("meta", "total")).to eq(2)
    expect(issue.occurrences.count).to eq(2)
    get "/api/v1/issues/#{issue.id}/occurrences", params: { view: "activity", limit: 1 }
    expect(JSON.parse(response.body).fetch("activity_groups").sole["correlated"]).to eq(false)
  end

  it "does not turn ambiguous retained paths into a representative restoration target" do
    issue = create_issue(target_type: "user_home_t")
    occurrence = create_occurrence(issue)
    occurrence.normalized_denial.update!(target_type: "user_home_t", details: {
      "target_evidence" => { "filesystem_paths" => ["/var/www/html/a.html", "/var/www/html/b.html"] }
    })
    get "/api/v1/issues/#{issue.id}"
    body = JSON.parse(response.body)
    expect(body["triage_guidance"]).to be_nil
    expect(body.dig("operator_guidance", "source", "path")).to be_nil
    expect(body.dig("operator_guidance", "checks")).to be_empty
  end

  def create_issue(digest = "digest-#{SecureRandom.hex(4)}", source_type = "httpd_t", **attributes)
    attrs = {
      organization: Organization.sole,
      fingerprint_version: 4,
      fingerprint_digest: digest,
      source_type: source_type,
      target_type: Issue.exists?(organization: Organization.sole, source_type: source_type, target_type: "default_t", target_class: "file") ? "test_#{Issue.count}_t" : "default_t",
      target_class: "file",
      permissions: ["read"],
      first_seen_at: Time.current,
      last_seen_at: Time.current
    }.merge(attributes)
    issue = Issue.create!(attrs)
    fingerprint = FingerprintV3.call(attrs)
    issue.signatures.create!(fingerprint_version: 3, fingerprint_digest: fingerprint.fetch(:digest), permissions: issue.permissions,
      first_seen_at: issue.first_seen_at, last_seen_at: issue.last_seen_at)
    issue
  end

  def create_occurrence(issue, external_id = "host-1", sequence = 1, host: nil, occurred_at: nil)
    organization = issue.organization
    host ||= Host.create!({ organization: organization, external_id: external_id, hostname: "web-#{external_id.delete_prefix("host-")}" })
    snapshot = HostSnapshot.create!({ host: host, details: { "id" => external_id } })
    installation = AgentInstallation.create!({ organization: organization, name: "agent-#{external_id}" })
    audit = occurred_at || Time.utc(2026, 9, 13) + sequence.seconds
    raw_event = RawEvent.create!({
      organization: organization, agent_installation: installation, host: host, host_snapshot: snapshot,
      audit_timestamp: audit, audit_sequence: sequence, boot_id: "boot-#{external_id}",
      completion_reason: "eoe", evidence_digest: external_id == "host-1" ? "raw-digest" : "raw-digest-#{external_id}",
      host_observed_at: Time.current, agent_received_at: Time.current, server_received_at: Time.current, schema_version: 2
    })
    denial = NormalizedDenial.create!({
      raw_event: raw_event, ordinal: 0, normalization_version: 1, status: "ok",
      source_type: "httpd_t", target_type: "default_t", target_class: "file", permissions: ["read"]
    })
    occurrence = Occurrence.create!({ organization: organization, host: host, host_snapshot: snapshot, raw_event: raw_event, normalized_denial: denial, issue: issue, issue_signature: issue.signatures.first, occurred_at: audit })
    occurrence
  end

  def csrf_token
    get "/api/v1/issues"
    response.headers["X-CSRF-Token"]
  end

  def json_headers(token)
    { "Content-Type" => "application/json", "X-CSRF-Token" => token }
  end

  def observe_host(external_id, details)
    organization = Organization.sole
    host = Host.create!(organization: organization, external_id: external_id, hostname: external_id)
    snapshot = HostSnapshot.create!(host: host, details: details)
    installation = AgentInstallation.create!(organization: organization, name: "obs-agent-#{external_id}", bound_host: host)
    host.host_snapshot_observations.create!(agent_installation: installation, host_snapshot: snapshot, first_observed_at: Time.current, last_observed_at: Time.current, first_received_at: Time.current, last_received_at: Time.current)
    host
  end

  def create_ungroupable_event(external_id, occurred_at: Time.current)
    organization = Organization.sole
    host = Host.create!(organization: organization, external_id: external_id, hostname: external_id)
    snapshot = HostSnapshot.create!(host: host, details: { "id" => external_id })
    installation = AgentInstallation.create!(organization: organization, name: "agent-#{external_id}")
    raw_event = RawEvent.create!(
      organization: organization, agent_installation: installation, host: host, host_snapshot: snapshot,
      audit_timestamp: occurred_at, audit_sequence: 1, boot_id: "boot-#{external_id}",
      completion_reason: "eoe", evidence_digest: "ungroupable-#{external_id}",
      host_observed_at: Time.current, agent_received_at: Time.current, server_received_at: Time.current, schema_version: 2
    )
    denial = NormalizedDenial.create!(raw_event: raw_event, ordinal: 0, normalization_version: 1, status: "ungroupable", details: { "missing" => ["scontext"] })
    Occurrence.create!(organization: organization, host: host, host_snapshot: snapshot, raw_event: raw_event, normalized_denial: denial, occurred_at: occurred_at)
  end

  def configure_policy_occurrence(occurrence, result:, identity:, boolean: nil, boolean_name: "httpd_can_network_connect", matching_rule: nil, fact_extra: {})
    policy_identity = identity.match?(PolicyArtifact::IDENTITY_FORMAT) ? identity : "sha256:#{Digest::SHA256.hexdigest(identity)}"
    rules = result == "matched" ? [matching_rule || "allow httpd_t unreserved_port_t:tcp_socket name_connect; [ #{boolean_name} ]:True"] : []
    occurrence.host_snapshot.update!(details: { "selinux" => { "policy_identity" => policy_identity, "booleans" => boolean.nil? ? [] : [{ "name" => boolean_name, "current" => boolean, "status" => "observed" }] } })
    occurrence.normalized_denial.update!(source_type: "httpd_t", target_type: "unreserved_port_t", target_class: "tcp_socket", permissions: ["name_connect"], details: { "enforcement_mode" => "enforcing", "network_evidence" => { "dport_fields" => ["12345"] }, "syscall_evidence" => [{ "syscall" => "connect", "success" => "no" }] })
    fact = PolicyFact.create_or_find_by!(policy_identity: policy_identity, query_kind: PolicyFact::QUERY_KIND,
      source_type: "httpd_t", target_type: "unreserved_port_t", object_class: "tcp_socket", permission: "name_connect")
    fact.update!(status: result, evaluator_version: "sesearch-4.4.4", matching_rules: (Array(fact.matching_rules) + rules).uniq, evaluated_at: Time.current)
  end

  def configure_file_context_occurrence(occurrence, context:, expected_context:, enforcement: "enforcing")
    occurrence.normalized_denial.update!(
      target_context: context,
      target_type: context.split(":", 4)[2],
      details: { "enforcement_mode" => enforcement, "target_evidence" => { "filesystem_paths" => ["/srv/app/data"], "object_names" => [] } }
    )
    occurrence.raw_event.update!(file_context_observations: [{
      "kind" => "expected_context", "path" => "/srv/app/data", "object_class" => "file", "file_type" => "file",
      "status" => "resolved", "expected_context" => expected_context,
      "observed_at" => Time.current.iso8601(6), "resolver" => "matchpathcon"
    }])
  end

  def host_explanation(issue)
    get "/api/v1/issues/#{issue.id}/analysis"
    JSON.parse(response.body).dig("host_explanations").first
  end
end
