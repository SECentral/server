require "rails_helper"

RSpec.describe Occurrence do
  it "keeps the issue occurrence counter consistent when destroyed" do
    issue = Issue.create!(organization: Organization.create!(name: "counter"), fingerprint_version: 3, fingerprint_digest: "digest", source_type: "httpd_t", target_type: "default_t", target_class: "file", first_seen_at: Time.current, last_seen_at: Time.current)
    host = Host.create!(organization: issue.organization, external_id: "host-1")
    snapshot = HostSnapshot.create!(host: host, details: {})
    installation = AgentInstallation.create!(organization: issue.organization, name: "agent-1")
    raw_event = RawEvent.create!(organization: issue.organization, agent_installation: installation, host: host, host_snapshot: snapshot, audit_timestamp: Time.current, audit_sequence: 1, boot_id: "boot-1", completion_reason: "eoe", evidence_digest: "raw", host_observed_at: Time.current, agent_received_at: Time.current, server_received_at: Time.current, schema_version: 2)
    denial = NormalizedDenial.create!(raw_event: raw_event, ordinal: 0, normalization_version: 1, status: "ok", source_type: "httpd_t", target_type: "default_t", target_class: "file", permissions: ["read"])
    occurrence = Occurrence.create!(organization: issue.organization, host: host, host_snapshot: snapshot, raw_event: raw_event, normalized_denial: denial, issue: issue, occurred_at: Time.current)

    expect(issue.reload.occurrences_count).to eq(1)
    occurrence.destroy!
    expect(issue.reload.occurrences_count).to eq(0)
  end
end
