class OccurrenceDetailSerializer
  def self.call(occurrence, guidance: nil)
    denial = occurrence.normalized_denial
    raw_event = occurrence.raw_event
    {
      id: occurrence.id,
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
        details: denial.details
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
        checkpoint_policy_identity: raw_event.checkpoint_policy_identity(occurrence.host_snapshot),
        completion_reason: raw_event.completion_reason,
        evidence_digest: raw_event.evidence_digest,
        file_context_observations: raw_event.file_context_observations,
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
