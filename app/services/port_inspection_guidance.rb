class PortInspectionGuidance
  def self.call(denial)
    endpoint = PortMappingGuidance.endpoint(denial)
    return [] unless endpoint && endpoint[:port]

    target = "#{endpoint[:protocol]}/#{endpoint[:port]}"
    checks = []
    if endpoint[:operation] == "name_bind"
      checks << { kind: :socket_listeners, reason: "Inspect current listeners and ownership for #{target}.",
        expected: "Compare the listening address and process owner with the intended service. Process details may require additional privileges." }
    end
    checks << { kind: :port_classification, reason: "Inspect the current SELinux port classification for #{target}.",
      expected: "Find the port within the protocol's individual entries or ranges and compare its type with the recorded AVC label." }
    checks << { kind: :port_local_classification, reason: "Inspect local SELinux port overrides for #{target}.",
      expected: "Compare local overrides and record boundaries with the effective listing; stop for conflicting ownership or changed prior state." }
    if denial.source_type.to_s.match?(/\A[A-Za-z][A-Za-z0-9_]*\z/)
      checks << { kind: :port_policy_alternatives, source_type: denial.source_type, object_class: denial.target_class,
        reason: "Inspect current local policy alternatives.",
        expected: "Inspect matching target types, attributes and conditions in the host's currently loaded policy." }
    end
    checks.map { |check| check.merge(endpoint).merge(target: target, limitation: :current_state_only) }
  end
end
