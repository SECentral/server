class OccurrenceDetailSerializer
  def self.policy_states(occurrences)
    PolicyPermissiveDomains.for_identities(occurrences.map { |occurrence| occurrence.raw_event.checkpoint_policy_identity(occurrence.host_snapshot) })
  end

  def self.call(occurrence, guidance: nil, policy_states: nil)
    denial = occurrence.normalized_denial
    raw_event = occurrence.raw_event
    {
      id: occurrence.id,
      issue_signature_id: occurrence.issue_signature_id,
      host: { id: occurrence.host_id, hostname: occurrence.host.hostname },
      occurred_at: occurrence.occurred_at,
      normalized_denial: {
        status: denial.status,
        source_type: denial.source_type,
        target_type: denial.target_type,
        target_class: denial.target_class,
        permissions: denial.permissions,
        target_paths: denial.target_paths,
        source_context: denial.source_context,
        target_context: denial.target_context,
        command: denial.command,
        executable: denial.executable,
        details: denial.details.merge("event_file_contexts" => RawEvent.effective_context_observations(denial.details["event_file_contexts"], raw_event.checkpoint_invalidated_fields))
      },
      raw_event: {
        id: raw_event.id,
        audit_timestamp: raw_event.audit_timestamp,
        audit_sequence: raw_event.audit_sequence,
        boot_id: raw_event.boot_id,
        category: raw_event.category,
        transition_type: raw_event.transition_type,
        checkpoint_enforcement_mode: raw_event.checkpoint_enforcement_mode(occurrence.host_snapshot),
        checkpoint_invalidated_fields: raw_event.checkpoint_invalidated_fields,
        checkpoint_port_inventory_status: raw_event.checkpoint_port_inventory(occurrence.host_snapshot)["status"],
        checkpoint_file_context_mappings_status: raw_event.checkpoint_trust(occurrence.host_snapshot).file_context_mappings["status"],
        checkpoint_policy_identity: raw_event.checkpoint_policy_identity(occurrence.host_snapshot),
        checkpoint: {
          snapshot_id: occurrence.host_snapshot_id,
          observed_at: raw_event.host_observed_at,
          kernel_release: occurrence.host_snapshot&.details&.dig("platform", "kernel_release")
        },
        collection: {
          agent_installation_id: raw_event.agent_installation_id,
          schema_version: raw_event.schema_version,
          agent_received_at: raw_event.agent_received_at,
          server_received_at: raw_event.server_received_at
        },
        permissive_policy_state: PolicyPermissiveDomains.for_occurrence(occurrence, policy_states),
        completion_reason: raw_event.completion_reason,
        evidence_digest: raw_event.evidence_digest,
        file_context_observations: raw_event.effective_file_context_observations,
        audit_records: raw_event.raw_audit_records.map do |record|
          {
            position: record.position,
            record_type: record.record_type,
            type_name: record.type_name,
            audit_timestamp: record.audit_timestamp,
            sequence: record.sequence,
            payload: record.payload
          }
        end
      },
      guidance: guidance,
      issue: occurrence.issue ? { id: occurrence.issue.id } : nil
    }
  end
end
