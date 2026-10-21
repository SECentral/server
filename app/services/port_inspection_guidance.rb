class PortInspectionGuidance
  def self.call(denial)
    endpoint = PortMappingGuidance.endpoint(denial)
    return [] unless endpoint && endpoint[:port]

    target = "#{endpoint[:protocol]}/#{endpoint[:port]}"
    checks = []
    if endpoint[:operation] == "name_bind"
      checks << { kind: :socket_listeners, reason: "Inspect current listeners and ownership for #{target}.",
        expected: "Compare the listening address and owner with the intended service. No listener does not establish the cause; process details may require additional privileges." }
    end
    checks << { kind: :port_classification, reason: "Inspect the current SELinux port classification for #{target}.",
      expected: "Find the port within the protocol's individual entries or ranges. Compare its type with the recorded AVC target type; classification alone does not establish the correct service type." }
    checks << { kind: :port_local_classification, reason: "Inspect local SELinux port overrides for #{target}.",
      expected: "Compare local overrides and record boundaries with the effective listing. No local override does not mean no effective mapping; stop for conflicting ownership or changed prior state." }
    if denial.source_type.to_s.match?(/\A[A-Za-z][A-Za-z0-9_]*\z/)
      checks << { kind: :port_policy_alternatives, source_type: denial.source_type, object_class: denial.target_class,
        reason: "Inspect current local policy alternatives.",
        expected: "Queries the host's currently loaded policy, not the stored checkpoint. Inspect target attributes and conditions; a matching rule does not establish service intent or an appropriate replacement classification. Use this when central evaluation is pending or failed." }
    end
    checks.map { |check| check.merge(endpoint).merge(target: target, limitation: :current_state_only) }
  end
end
