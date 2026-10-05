class PersistNormalizedDenial
  OWNED_DETAIL_KEYS = %w[
    missing target_evidence network_evidence process_evidence syscall_evidence
    permissive enforcement_mode event_file_contexts policy_evaluations evidence_provenance
  ].freeze

  def self.call(raw_event, result, ordinal:, normalization_version:)
    denial = raw_event.normalized_denials.find_or_initialize_by({ normalization_version: normalization_version, ordinal: ordinal })
    denial.assign_attributes(
      status: result.fetch(:status),
      source_context: result[:source_context],
      source_type: result[:source_type],
      target_context: result[:target_context],
      target_type: result[:target_type],
      target_class: result[:target_class],
      permissions: result[:permissions] || [],
      command: result[:command],
      executable: result[:executable],
      target_paths: result[:target_paths] || [],
      details: denial.details.to_h.except(*OWNED_DETAIL_KEYS).merge(normalized_details(raw_event, result))
    )
    denial.save!
    denial
  end

  def self.normalized_details(raw_event, result)
    {
      "missing" => result[:missing] || [],
      "target_evidence" => result[:target_evidence] || { path_fields: [], filesystem_paths: [], object_names: [] },
      "network_evidence" => result[:network_evidence] || { dest_fields: [], dport_fields: [], lport_fields: [], proto_fields: [], bind_port_fields: [], operations: [] },
      "process_evidence" => result[:process_evidence] || { pids: [], commands: [], executables: [], source_contexts: [] },
      "syscall_evidence" => result[:syscall_evidence] || [],
      "permissive" => result[:permissive],
      "enforcement_mode" => result[:permissive].nil? ? "unknown" : result[:permissive] ? "permissive" : "enforcing",
      "event_file_contexts" => raw_event.file_context_observations,
      "policy_evaluations" => raw_event.policy_evaluations,
      "evidence_provenance" => result[:evidence_provenance] || []
    }
  end
  private_class_method :normalized_details
end
