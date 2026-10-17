module PortResolutionFixtures
  def port_range(type, start, finish = start, provenance: "not_confirmed_custom", protocol: "tcp")
    { "type" => type, "protocol" => protocol, "ports" => [{ "start" => start, "end" => finish, "provenance" => provenance }] }
  end

  def port_fixture(operation: "name_bind", protocol: "tcp", port: 12345, mappings: nil, issue: nil)
    org = issue&.organization || Organization.find_or_create_by!(name: "port-resolution")
    issue ||= Issue.create!(organization: org, fingerprint_version: 3, fingerprint_digest: SecureRandom.hex,
      source_type: "httpd_t", target_type: "unreserved_port_t", target_class: "#{protocol}_socket", permissions: [operation],
      first_seen_at: 1.minute.ago, last_seen_at: 1.minute.ago)
    host = Host.create!(organization: org, external_id: SecureRandom.hex, hostname: "web-#{SecureRandom.hex(3)}", last_seen_at: Time.current)
    agent = AgentInstallation.create!(organization: org, name: "port-test")
    identity = "sha256:#{SecureRandom.hex(32)}"
    mappings ||= [port_range("unreserved_port_t", 1024, 32767, protocol: protocol), port_range("http_port_t", 80, protocol: protocol)]
    snapshot = HostSnapshot.create!(host: host, details: { "boot_id" => "boot", "selinux" => { "policy_identity" => identity,
      "boolean_status" => "observed", "booleans" => [], "policy" => { "port_inventory" => {
        "status" => "observed", "local_classification_status" => "observed", "mappings" => mappings } } } })
    host.host_snapshot_observations.create!(agent_installation: agent, host_snapshot: snapshot,
      first_observed_at: 2.minutes.ago, last_observed_at: 2.minutes.ago, first_received_at: Time.current, last_received_at: Time.current)
    raw = RawEvent.create!(organization: org, host: host, agent_installation: agent, host_snapshot: snapshot,
      audit_timestamp: 1.minute.ago, audit_sequence: 1, boot_id: "boot", completion_reason: "eoe", evidence_digest: "port",
      schema_version: 2, host_observed_at: 2.minutes.ago, agent_received_at: Time.current, server_received_at: Time.current)
    denial = NormalizedDenial.create!(raw_event: raw, normalization_version: 1, ordinal: 0, status: "ok", source_type: issue.source_type,
      target_type: issue.target_type, target_class: issue.target_class, permissions: [operation], command: "httpd",
      details: { "enforcement_mode" => "enforcing", "network_evidence" => {
        "bind_port_fields" => operation == "name_bind" ? [port.to_s] : [], "dest_fields" => operation == "name_connect" ? [port.to_s] : ["9999"] } })
    occurrence = Occurrence.create!(organization: org, issue: issue, host: host, host_snapshot: snapshot, raw_event: raw,
      normalized_denial: denial, occurred_at: raw.audit_timestamp)
    rule = "allow httpd_t http_port_t:#{protocol}_socket #{operation};"
    fact = PolicyFact.create!(policy_identity: identity, query_kind: PolicyFact::PORT_QUERY_KIND, source_type: "httpd_t",
      target_type: "port_type", object_class: "#{protocol}_socket", permission: operation, status: "matched", evaluator_version: "SETools test",
      matching_rules: [rule], rule_details: [{ "rule" => rule, "target_types" => ["http_port_t"] },
        { "kind" => "port_contexts", "protocol" => protocol, "mappings" => mappings.select { |mapping| mapping["protocol"] == protocol }.flat_map { |mapping| mapping["ports"].map { |range| range.slice("start", "end").merge("type" => mapping["type"]) } } }])
    [issue, occurrence, host, snapshot, fact]
  end

  def replace_port_snapshot(host, snapshot, patch)
    latest = HostSnapshot.create!(host: host, details: snapshot.details.deep_merge(patch))
    host.host_snapshot_observations.first.update!(host_snapshot: latest, last_observed_at: Time.current)
    host.reload
    latest
  end
end
