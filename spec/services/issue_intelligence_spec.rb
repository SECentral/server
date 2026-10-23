require "rails_helper"

RSpec.describe IssueIntelligence do
  after do
    Occurrence.delete_all
    NormalizedDenial.delete_all
    PolicyFact.delete_all
    PolicyArtifact.delete_all
    IssueDispositionChange.delete_all
    Issue.delete_all
    RawEvent.delete_all
    HostSnapshotObservation.delete_all
    HostSnapshot.delete_all
    AgentInstallation.delete_all
    Host.delete_all
    Organization.delete_all
  end

  it "separates occurrence-time snapshots from current fleet state" do
    organization = Organization.create!(name: "intelligence")
    issue = Issue.create!(organization: organization, fingerprint_version: 3, fingerprint_digest: "digest", source_type: "httpd_t", target_type: "default_t", target_class: "file", first_seen_at: 1.day.ago, last_seen_at: Time.current)
    affected = create_host(organization, "affected", "42", [])
    current_snapshot = observe(affected, host_details("43", []), Time.current)
    unaffected = create_host(organization, "unaffected", "42", [["local_web", 400]])
    old_snapshot = affected.host_snapshots.where.not(id: current_snapshot.id).first

    create_occurrence(issue, affected, old_snapshot, 1.day.ago)
    create_occurrence(issue, affected, current_snapshot, 1.hour.ago, 2)
    create_occurrence(issue, affected, old_snapshot, 2.hours.ago, 3)

    result = described_class.call(issue)

    expect(result[:occurrence_time][:policy_distribution]).to eq("42" => 2, "43" => 1)
    expect(result[:fleet]).to include(activity_hosts: 2, current_configuration_hosts: 2, hosts_with_occurrence: 1, hosts_without_occurrence: 1)
    expect(result[:fleet][:comparison_requirement]).to be_nil
    expect(result[:fleet][:with_occurrence_policies]).to eq("43" => 1)
    expect(result[:fleet][:without_occurrence_policies]).to eq("42" => 1)
    expect(result[:fleet][:without_occurrence_modules]).to eq(["local_web", 400, "unknown"] => 1)
    expect(result[:fleet][:with_occurrence_file_contexts]).to eq({})
    expect(result[:fleet][:without_occurrence_file_contexts]).to eq({})
    expect(unaffected).to be_present
  end

  it "excludes stale and event-only hosts from current configuration while retaining their occurrences" do
    organization = Organization.create!(name: "configuration-eligibility")
    issue = Issue.create!(organization: organization, fingerprint_version: 3, fingerprint_digest: "eligibility", source_type: "httpd_t", target_type: "default_t", target_class: "file", first_seen_at: 1.day.ago, last_seen_at: Time.current)
    stale = create_host(organization, "stale", "42", [])
    stale.current_state_observation.update!(last_received_at: 1.hour.ago)
    create_occurrence(issue, stale, stale.current_snapshot, Time.current)
    event_only = organization.hosts.create!(external_id: "event-only", hostname: "event-only", last_seen_at: Time.current)
    event_snapshot = event_only.host_snapshots.create!(details: host_details("42", []))
    create_occurrence(issue, event_only, event_snapshot, Time.current, 2)
    create_host(organization, "fresh", "42", [])

    result = described_class.call(issue)

    expect(result[:affected_hosts]).to eq(2)
    expect(result[:fleet]).to include(activity_hosts: 3, current_configuration_hosts: 1, hosts_with_occurrence: 0, hosts_without_occurrence: 1)
  end

  it "explains comparison prerequisites with the configured reporting windows and retained occurrence history" do
    stub_const("Host::STALE_AFTER", 7.minutes)
    allow(Rails.application.config.x.agent_reporting).to receive(:stale_after).and_return(1.hour)
    organization = Organization.create!(name: "comparison-windows")
    issue = Issue.create!(organization: organization, fingerprint_version: 3, fingerprint_digest: "windows", source_type: "httpd_t", target_type: "default_t", target_class: "file", first_seen_at: 1.day.ago, last_seen_at: 1.day.ago)
    affected = create_host(organization, "affected", "42", [])
    create_occurrence(issue, affected, affected.current_snapshot, 1.day.ago)
    affected.update!(last_seen_at: 1.hour.ago)
    affected.current_state_observation.update!(last_received_at: 2.hours.ago)
    expect(described_class.call(issue).dig(:fleet, :comparison_requirement)).to eq("Fleet comparison needs hosts reporting within the last 7 minutes.")

    affected.update!(last_seen_at: Time.current)
    expect(described_class.call(issue).dig(:fleet, :comparison_requirement)).to eq("Fleet comparison needs host configuration confirmed within the last 1 hour.")
    affected.current_state_observation.update!(last_received_at: Time.current)
    expect(described_class.call(issue).dig(:fleet, :comparison_requirement)).to eq("Fleet comparison needs at least two hosts with configuration confirmed within the last 1 hour.")
    other = create_host(organization, "other", "42", [])
    expect(described_class.call(issue).dig(:fleet, :comparison_requirement)).to be_nil

    affected.current_state_observation.update!(last_received_at: 2.hours.ago)
    create_host(organization, "another", "42", [])
    expect(described_class.call(issue).dig(:fleet, :comparison_requirement)).to include("report within the last 7 minutes", "configuration within the last 1 hour")
    affected.current_state_observation.update!(last_received_at: Time.current)
    create_occurrence(issue, other, other.current_snapshot, 1.day.ago)
    another = organization.hosts.find_by!(external_id: "another")
    create_occurrence(issue, another, another.current_snapshot, 1.day.ago)
    expect(described_class.call(issue).dig(:fleet, :comparison_requirement)).to eq("All eligible hosts have recorded this issue. Comparison needs a host with no recorded occurrence.")
  end

  it "skips analysis-only fleet work when building issue detail intelligence" do
    organization = Organization.create!(name: "detail-intelligence")
    issue = Issue.create!(organization: organization, fingerprint_version: 3, fingerprint_digest: "detail", source_type: "httpd_t", target_type: "default_t", target_class: "file", first_seen_at: 1.day.ago, last_seen_at: Time.current)
    host = create_host(organization, "affected", "42", [])
    create_occurrence(issue, host, host.current_snapshot, Time.current)
    intelligence = described_class.new(issue, include_analysis: false)

    expect(intelligence).not_to receive(:configuration_drift)
    expect(intelligence).not_to receive(:current_file_context_matches)
    expect(intelligence).not_to receive(:fleet_analysis)

    result = intelligence.call

    expect(result[:fleet]).to include(activity_hosts: 1, current_configuration_hosts: 1, hosts_with_occurrence: 1, hosts_without_occurrence: 0)
    expect(result).not_to have_key(:configuration_drift)
    expect(result).not_to have_key(:current_file_context_matches)
  end

  it "keeps event file labels and booleans separate from heartbeat current state" do
    organization = Organization.create!(name: "event-evidence")
    issue = Issue.create!(organization: organization, fingerprint_version: 3, fingerprint_digest: "event-evidence", source_type: "httpd_t", target_type: "user_home_t", target_class: "file", permissions: ["read"], first_seen_at: 1.day.ago, last_seen_at: Time.current)
    host = organization.hosts.create!(external_id: "host", hostname: "host", last_seen_at: Time.current)
    event_snapshot = host.host_snapshots.create!(details: { "selinux" => { "booleans" => [{ "name" => "httpd_read_user_content", "current" => false, "status" => "observed" }] } })
    identity = "sha256:" + "d" * 64
    event_snapshot.update!(details: event_snapshot.details.deep_merge("selinux" => { "policy_identity" => identity }))
    heartbeat_details = host_details("42", [])
    heartbeat_details["selinux"]["booleans"] = [{ "name" => "httpd_read_user_content", "current" => true, "status" => "observed" }]
    heartbeat_details["selinux"]["policy"]["file_contexts"] = [{ "pattern" => "/srv/app", "file_type" => "all files", "context" => "system_u:object_r:heartbeat_t:s0" }]
    observe(host, heartbeat_details, Time.current)
    details = {
      "target_evidence" => { "filesystem_paths" => ["/srv/app"], "object_names" => [] },
      "event_file_contexts" => [{ "path" => "/srv/app", "status" => "observed", "context" => "system_u:object_r:event_t:s0", "expected_status" => "observed", "expected_context" => "system_u:object_r:expected_t:s0" }],
      "policy_evaluations" => [{ "source_type" => "httpd_t", "target_type" => "user_home_t", "target_class" => "file", "permissions" => ["read"], "policy_identity" => "sha256:policy", "evaluator_version" => "sesearch", "result" => "matched", "matching_rules" => ["allow httpd_t user_home_t:file read; [ httpd_read_user_content ]:True"] }],
      "enforcement_mode" => "enforcing"
    }
    occurrence = create_occurrence(issue, host, event_snapshot, Time.current, 1, details: details)
    occurrence.normalized_denial.update!(target_type: "user_home_t", target_context: "unconfined_u:object_r:user_home_t:s0")
    occurrence.raw_event.update!(file_context_observations: [{
      "kind" => "expected_context", "path" => "/srv/app", "object_class" => "file", "file_type" => "file",
      "expected_context" => "system_u:object_r:expected_t:s0", "observed_at" => Time.current.iso8601(6),
      "resolver" => "matchpathcon", "status" => "resolved"
    }])
    PolicyFact.create!(policy_identity: identity, query_kind: PolicyFact::QUERY_KIND, source_type: "httpd_t", target_type: "user_home_t", object_class: "file", permission: "read", status: "matched", evaluator_version: "sesearch-4.4.4", matching_rules: ["allow httpd_t user_home_t:file read; [ httpd_read_user_content ]:True"], evaluated_at: Time.current)

    result = described_class.call(issue)
    diagnosis = IssueDiagnosis.call(issue, intelligence: result)


    expect(host.current_snapshot.details.dig("selinux", "booleans", 0, "current")).to be(true)
    expect(result[:event_file_contexts].first.fetch("context")).to eq("system_u:object_r:event_t:s0")
    expect(result[:expected_context_observations].first.fetch("expected_context")).to eq("system_u:object_r:expected_t:s0")
    expect(result[:policy_evaluation][:booleans].first.fetch("current")).to be(false)
    expect(diagnosis).to include(kind: "file_context_mismatch", temporal_scope: "avc_vs_expected_context_inspection")
    expect(diagnosis[:evidence].second).to include(basis: "expected_context_observation")
  end

  private

  def host_details(policy, modules)
    { "platform" => { "os_id" => "rhel", "os_version" => "9" }, "selinux" => { "enforcement" => "enforcing", "kernel_policy_version" => policy, "policy" => { "custom_modules" => modules.map { |name, priority| { "name" => name, "priority" => priority } } } } }
  end

  def create_host(organization, id, policy, modules)
    host = organization.hosts.create!(external_id: id, hostname: id, last_seen_at: Time.current)
    observe(host, host_details(policy, modules), 1.minute.ago)
    host
  end

  def observe(host, details, at)
    snapshot = host.host_snapshots.create!(details: details)
    installation = host.agent_installations.first || host.organization.agent_installations.create!(name: "agent-#{host.external_id}", bound_host: host)
    host.host_snapshot_observations.create!(agent_installation: installation, host_snapshot: snapshot, first_observed_at: at, last_observed_at: at, first_received_at: at, last_received_at: at)
    snapshot
  end

  def create_occurrence(issue, host, snapshot, timestamp, sequence = 1, details: { "target_evidence" => { "filesystem_paths" => [], "object_names" => [] } })
    installation = issue.organization.agent_installations.create!(name: "event-agent-#{host.external_id}-#{sequence}")
    raw_event = RawEvent.create!(organization: issue.organization, agent_installation: installation, host: host, host_snapshot: snapshot, audit_timestamp: timestamp, audit_sequence: sequence, boot_id: "boot-#{host.external_id}", completion_reason: "eoe", evidence_digest: "digest-#{host.external_id}-#{sequence}", host_observed_at: timestamp, agent_received_at: timestamp, server_received_at: timestamp, schema_version: 2)
    denial = NormalizedDenial.create!(raw_event: raw_event, ordinal: 0, normalization_version: 1, status: "ok", source_type: "httpd_t", target_type: "default_t", target_class: "file", permissions: ["read"], details: details)
    Occurrence.create!(organization: issue.organization, host: host, host_snapshot: snapshot, raw_event: raw_event, normalized_denial: denial, issue: issue, occurred_at: timestamp)
  end
end
