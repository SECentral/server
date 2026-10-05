require "rails_helper"

RSpec.describe PersistNormalizedDenial do
  after do
    NormalizedDenial.delete_all
    RawEvent.delete_all
    HostSnapshot.delete_all
    AgentInstallation.delete_all
    Host.delete_all
    Organization.delete_all
  end

  it "replaces normalization-owned details while preserving additive evidence" do
    organization = Organization.create!(name: "persistence")
    host = organization.hosts.create!(external_id: "host")
    snapshot = host.host_snapshots.create!(details: {})
    installation = organization.agent_installations.create!(name: "agent", bound_host: host)
    raw_event = organization.raw_events.create!(agent_installation: installation, host: host, host_snapshot: snapshot, audit_timestamp: Time.current, audit_sequence: 1, boot_id: "boot", completion_reason: "eoe", evidence_digest: "digest", host_observed_at: Time.current, agent_received_at: Time.current, server_received_at: Time.current, schema_version: 2)

    denial = described_class.call(raw_event, result(paths: ["/old"], syscall: "old"), ordinal: 0, normalization_version: 1)
    denial.update!(details: denial.details.merge("future_evidence" => { "version" => 2 }))

    described_class.call(raw_event, result(paths: ["/new"], syscall: "new"), ordinal: 0, normalization_version: 1)

    expect(denial.reload.details).to include(
      "future_evidence" => { "version" => 2 },
      "target_evidence" => include("filesystem_paths" => ["/new"]),
      "syscall_evidence" => [{ "syscall" => "new" }]
    )
  end

  def result(paths:, syscall:)
    {
      status: "ok", source_context: "system_u:system_r:httpd_t:s0", source_type: "httpd_t",
      target_context: "system_u:object_r:default_t:s0", target_type: "default_t", target_class: "file",
      permissions: ["read"], target_paths: paths,
      target_evidence: { path_fields: paths, filesystem_paths: paths, object_names: [] },
      network_evidence: { "dest_fields" => [], "dport_fields" => [], "lport_fields" => [], "proto_fields" => [], "bind_port_fields" => [], "operations" => [] },
      process_evidence: { "pids" => [], "commands" => [], "executables" => [], "source_contexts" => [] },
      syscall_evidence: [{ "syscall" => syscall }], permissive: false, evidence_provenance: []
    }
  end
end
