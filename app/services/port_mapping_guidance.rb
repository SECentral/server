require "shellwords"

# Policy possibilities and host observations remain separate until intent review.
class PortMappingGuidance
  GENERIC_TYPES = %w[port_t reserved_port_t hi_reserved_port_t unreserved_port_t].freeze
  PLAN_SEMANTICS_VERSION = 1

  def self.endpoint(denial)
    protocol = { "tcp_socket" => "tcp", "udp_socket" => "udp" }[denial.target_class]
    operation = Array(denial.permissions).one? ? Array(denial.permissions).sole : nil
    return unless protocol && %w[name_bind name_connect].include?(operation)
    return if operation == "name_connect" && protocol != "tcp"

    ports = operation == "name_bind" ? Array(denial.details.dig("network_evidence", "bind_port_fields")) : IssueIntelligence.destination_ports(denial.details)
    ports = ports.map(&:to_s).select { |port| port.match?(/\A\d+\z/) && port.to_i.between?(1, 65_535) }.map(&:to_i).uniq
    { protocol: protocol, operation: operation, port: ports.one? ? ports.first : nil }
  end

  def initialize(issue, occurrences:)
    @issue, @occurrences = issue, occurrences
    @facts, @states = {}, {}
  end

  def call
    investigations, proposals, seen = [], [], {}
    @occurrences.each do |occurrence|
      denial = occurrence.normalized_denial
      endpoint = self.class.endpoint(denial)
      next unless endpoint

      protocol, operation, port = endpoint.values_at(:protocol, :operation, :port)
      key = [occurrence.host_id, protocol, port, operation]
      if seen.key?(key)
        seen[key][:occurrence_count] += 1
        next
      end

      investigation = { host_id: occurrence.host_id, hostname: occurrence.host.hostname, occurrence_id: occurrence.id,
        protocol: protocol, port: port, operation: operation, observed_type: denial.target_type,
        occurred_at: occurrence.occurred_at, historical_policy_identity: occurrence.policy_identity,
        classification_differs: nil, policy_differs: nil,
        occurrence_count: 1, state: "unavailable", types: [], type_count: 0 }
      seen[key] = investigation
      investigations << investigation
      unless port
        investigation[:reason] = "A single nonzero #{operation == 'name_bind' ? 'local bind' : 'destination'} port was not retained. Identify the exact endpoint in the occurrence and service configuration; do not infer it from another event."
        next
      end
      proposals.concat(investigate(occurrence, investigation))
    end
    { investigations: investigations, proposals: proposals }
  end

  private

  def investigate(occurrence, investigation)
    host = occurrence.host
    state = @states[host.id] ||= host.selinux_state_for
    inventory = state.dig("policy", "port_inventory") || {}
    investigation.merge!(latest_observed_at: host.current_state_observation&.last_observed_at,
      inventory_status: inventory["status"] || "unknown", local_status: inventory["local_classification_status"] || "unknown")
    unless host.current_snapshot&.details&.dig("boot_id").present?
      return blocked(investigation, "Current host boot identity is missing. Refresh a same-host checkpoint before scoping a port-mapping plan.")
    end
    identity = state["policy_identity"]
    unless identity.to_s.match?(PolicyArtifact::IDENTITY_FORMAT)
      return blocked(investigation, "Current exact policy identity is missing or invalidated. Refresh the host checkpoint and policy artifact before evaluating alternative types.")
    end
    investigation[:current_policy_identity] = identity
    historical_identity = investigation[:historical_policy_identity]
    investigation[:policy_differs] = historical_identity != identity if historical_identity.to_s.match?(PolicyArtifact::IDENTITY_FORMAT)
    unless inventory["status"] == "observed" && inventory["local_classification_status"] == "observed"
      return blocked(investigation, "Effective port inventory is #{investigation[:inventory_status]}; local override classification is #{investigation[:local_status]}. Inspect semanage port -l and semanage port -l -C on this host and refresh complete inventory; absence is not established.")
    end
    ranges = ranges_for(inventory, investigation[:protocol])
    return blocked(investigation, "The retained protocol/range inventory is malformed. Inspect effective/local listings and refresh collection before review.") unless ranges
    covering = ranges.select { |range| range[:start] <= investigation[:port] && range[:end] >= investigation[:port] }
    investigation[:current_mappings] = covering
    local = covering.select { |range| range[:provenance] == "custom" }
    specific = covering.reject { |range| GENERIC_TYPES.include?(range[:type]) }
    current = local.presence || specific.presence || covering
    current_types = current.map { |range| range[:type] }.uniq
    investigation[:classification_differs] = current_types.first != investigation[:observed_type] if current_types.one?

    fact_key = [identity, investigation[:operation]]
    fact = @facts.fetch(fact_key) do
      @facts[fact_key] = PolicyFact.find_by(policy_identity: identity, query_kind: PolicyFact::PORT_QUERY_KIND,
        source_type: @issue.source_type, target_type: "port_type", object_class: @issue.target_class, permission: investigation[:operation])
    end
    unless fact && %w[matched no_match].include?(fact.status)
      unless @requested
        RequestResolutionPolicyFactsJob.perform_later(issue_id: @issue.id)
        @requested = true
      end
      return blocked(investigation, "Alternative port-type policy evaluation is #{fact&.status || 'pending'} for this host's exact policy. Wait for artifact evaluation or investigate its reported failure; no service type is inferred.", fact&.status == "error" ? "error" : "pending")
    end
    records = Array(fact.rule_details).find { |detail| detail["kind"] == "port_contexts" && detail["protocol"] == investigation[:protocol] }&.dig("mappings")
    return blocked(investigation, "Exact-policy port-record boundaries are missing. Refresh the port policy evaluation and inspect uncoalesced semanage listings before deciding add versus modify.") unless records.is_a?(Array)

    policy_covering = records.select { |record| record["start"] <= investigation[:port] && record["end"] >= investigation[:port] }
    unless policy_covering.map { |record| record["type"] }.uniq.sort == covering.map { |range| range[:type] }.uniq.sort
      return blocked(investigation, "The exact-policy port records and observed effective inventory conflict for this endpoint. Recheck loaded policy and effective/local mappings, then refresh evidence; no change is generated.")
    end
    rules = Array(fact.rule_details).select { |detail| detail["target_types"].is_a?(Array) && detail["rule"].in?(fact.matching_rules) }
    options = rules.flat_map { |rule| rule["target_types"] }.uniq.sort.filter_map do |type|
      next unless type.match?(/\A[A-Za-z][A-Za-z0-9_]*\z/)

      supporting = rules.select { |rule| rule["target_types"].include?(type) }
      active = supporting.select { |rule| active_rule?(rule, state, investigation[:operation]) }
      { type: type, permission: investigation[:operation], state: active.any? ? "supported" : "conditional",
        explanation: active.any? ? "An applicable exact-policy rule supplies #{investigation[:operation]} for this type under the latest observed conditions; intent and other permission checks remain unknown." : "Matching rules require inactive or unobserved conditions. Changing a mapping alone does not activate these rules.",
        existing_endpoints: ranges.select { |range| range[:type] == type }.first(3), active_rules: active,
        service: PortServiceDescriptions.for(type) }.compact
    end
    current_supported = current.map { |range| range[:type] }.uniq.one? && options.any? { |option| option[:state] == "supported" && current.any? { |range| range[:type] == option[:type] } }
    conflict = mapping_conflict(covering)
    if !conflict && local.any? && policy_covering.none? { |record| record["start"] == investigation[:port] && record["end"] == investigation[:port] && record["type"] == local.first[:type] }
      conflict = "Local provenance does not establish an exact singleton policy record. Inspect original range boundaries; no range modification is generated."
    end
    conditions_unmet = options.any? && options.none? { |option| option[:state] == "supported" }
    investigation[:state] = current_supported ? "no_change" : conflict || conditions_unmet ? "blocked" : "ready"
    investigation[:reason] = if current_supported
      "Current policy already supplies #{investigation[:operation]} for an observed classification. Check current Boolean/runtime state and retry the intended workload before changing a mapping; the historical AVC is not a fresh test."
    elsif conflict
      conflict
    elsif conditions_unmet
      "All matching alternative rules require inactive or unobserved conditions. Inspect their Boolean operands with getsebool and review the capability's purpose; a port mapping alone cannot activate a conditional rule."
    else
      "Exact policy offers possible port types for this operation. It does not establish which service belongs here."
    end
    stale = !host.current_configuration?
    if stale
      investigation[:state] = "blocked"
      investigation[:reason] = "The latest host configuration observation is stale. Inspect current effective/local mappings and refresh host evidence before reviewing a change."
    end
    investigation[:type_count] = options.size
    options = options.sort_by { |option| [current.any? { |range| range[:type] == option[:type] } ? 0 : 1, option[:state] == "supported" ? 0 : 1, option[:type]] }
    proposals = options.filter_map do |option|
      equivalent = current.map { |range| range[:type] }.uniq == [option[:type]]
      if equivalent
        option[:state] = "no_op"
        option[:explanation] = "This type is already observed for the protocol/port. No mapping command is needed; recheck runtime state and workload behavior."
      end
      next if equivalent || current_supported || conflict || option[:state] != "supported" || GENERIC_TYPES.include?(option[:type])

      proposal(occurrence, investigation, option, fact, state, covering, policy_covering, stale)
    end
    investigation[:types] = options.map { |option| option.except(:active_rules) }
    if options.empty?
      investigation[:state] = "unavailable"
      investigation[:reason] = "No applicable alternative port types were found in the evaluated exact policy. Review application endpoints, relevant Booleans or manual policy requirements; this is not an exhaustive remedy list."
    end
    proposals
  end

  def blocked(investigation, reason, state = "unavailable")
    investigation.merge!(reason: reason, state: state)
    []
  end

  def ranges_for(inventory, protocol)
    Array(inventory["mappings"]).select { |mapping| mapping["protocol"] == protocol }.flat_map do |mapping|
      return unless mapping["type"].to_s.match?(/\A[A-Za-z][A-Za-z0-9_]*\z/) && mapping["ports"].is_a?(Array)

      mapping["ports"].map do |range|
        return unless range["start"].is_a?(Integer) && range["end"].is_a?(Integer) && range["start"].between?(0, 65_535) && range["end"].between?(range["start"], 65_535)

        { type: mapping["type"], start: range["start"], end: range["end"], provenance: range["provenance"] }
      end
    end.uniq.sort_by { |range| [range[:start], range[:end], range[:type], range[:provenance].to_s] }
  end

  def mapping_conflict(covering)
    return "Range provenance is unknown. Inspect local overrides and refresh classification before deciding add versus modify." if covering.any? { |range| !%w[custom not_confirmed_custom].include?(range[:provenance]) }
    if covering.any? { |range| !GENERIC_TYPES.include?(range[:type]) }
      return "This protocol/port overlaps a service-specific classification (#{covering.map { |range| range[:type] }.uniq.join(', ')}). Confirm its owner and use another endpoint or request manual mapping review; no replacement command is generated."
    end
    local = covering.select { |range| range[:provenance] == "custom" }
    return "A local range or overlapping local records cover this port. Inspect their exact boundaries and owners; no range split or replacement is generated." if local.size > 1 || local.any? { |range| range[:start] != range[:end] }
    return "Overlapping base ranges have conflicting generic types. Resolve the effective classification on the host before review." if local.empty? && covering.map { |range| range[:type] }.uniq.size > 1

    nil
  end

  def active_rule?(rule, state, operation)
    match = PolicyRuleEvaluator::RULE.match(rule["rule"].to_s)
    return false unless match && match[3] == @issue.target_class && match[4].delete("{}").split.include?(operation)
    return true unless match[5]

    values = Array(state["booleans"]).to_h { |boolean| [boolean["name"], boolean["status"] == "observed" ? boolean["current"] : nil] }
    value = PolicyEvaluation::BooleanExpression.call(match[5], values)
    match[6] == "False" ? value == false : value == true
  end

  def proposal(occurrence, investigation, option, fact, state, covering, policy_covering, stale)
    protocol, port, type = investigation.values_at(:protocol, :port) + [option[:type]]
    exact = policy_covering.select { |record| record["start"] == port && record["end"] == port }
    prior_local = covering.find { |range| range[:provenance] == "custom" }
    action = exact.any? ? "modify" : "add"
    args = "-p #{Shellwords.escape(protocol)} -t #{Shellwords.escape(type)} #{port}"
    rollback = prior_local ? "sudo semanage port -m -p #{protocol} -t #{Shellwords.escape(prior_local[:type])} #{port}" : "sudo semanage port -d -p #{protocol} #{port}"
    booleans = option[:active_rules].flat_map { |rule| PolicyRuleEvaluator::RULE.match(rule["rule"])&.[](5).to_s.scan(/[A-Za-z][A-Za-z0-9_]*/) }.uniq.sort
    basis = investigation.slice(:host_id, :occurrence_id, :protocol, :port, :operation, :observed_type, :latest_observed_at).merge(
      target_port_type: type, action: action, prior_mappings: covering, prior_policy_records: policy_covering, current_policy_identity: fact.policy_identity,
      policy_fact_id: fact.id, matching_rules: option[:active_rules].map { |rule| rule["rule"] })
    effect = "Persistently classifies #{protocol.upcase}/#{port} as #{type} on this host. It can affect bind/connect decisions for other workloads using this port; it opens no firewall and guarantees no workload success."
    warning = "Inspect effective/local listings and listener ownership immediately before applying; stop if anything differs or another service owns this classification."
    limitations = ["Stored observations are not a fresh host inspection or proof of service intent.", "Other permissions, constraints, DAC, firewall and application configuration can still prevent access."]
    attributes = { title: "Classify #{protocol.upcase}/#{port} as #{type}", presentation: "primary",
      explanation: "Exact policy supports #{investigation[:operation]} from #{@issue.source_type} to #{type}; this does not establish which service should use the endpoint.",
      intent_prompt: "I confirm #{protocol.upcase}/#{port} on #{occurrence.host.hostname} is intended for the service represented by #{type}. I inspected effective/local ranges and ownership, verified no conflicting workload use, and accept this host-wide classification change.",
      scope_kind: "host_port", scope_description: "#{protocol.upcase}/#{port} on #{occurrence.host.hostname}; not per process or remote IP.",
      scope_warning: warning, expected_effect: effect, limitations: limitations,
      status: stale ? "evidence_changed" : "proposed" }
    attributes[:unavailable_reason] = investigation[:reason] if stale
    step = ->(title, command, explanation, persistence = "inspection") { { title: title, command: command, explanation: explanation, persistence: persistence } }
    plan = { preview_steps: [step.call("Inspect effective port ranges", "semanage port -l", "Verify #{protocol.upcase}/#{port} and all intersecting ranges against the recorded prior state."),
      step.call("Inspect local overrides", "semanage port -l -C", "Confirm local provenance and record boundaries; stop if the proposed #{action} no longer matches current state."),
      step.call(investigation[:operation] == "name_connect" ? "Inspect current outbound sockets" : "Inspect current listeners",
        investigation[:operation] == "name_connect" ? "ss -tnp" : protocol == "udp" ? "ss -lunp" : "ss -ltnp",
        investigation[:operation] == "name_connect" ? "Confirm the destination and owning workload using application configuration; absence of a socket does not establish the cause of a failed connection." : "Confirm the intended listening address, port and owner; stop for conflicting ownership or unintended exposure.")],
      apply_steps: [step.call("#{action.capitalize} the reviewed single-port mapping", "sudo semanage port -#{action == 'add' ? 'a' : 'm'} #{args}", effect, "port_mapping")],
      verification_steps: [step.call("Verify resulting effective classification", "semanage port -l", "Check #{protocol.upcase}/#{port} is #{type}; retry the actual #{investigation[:operation] == 'name_bind' ? 'service listener and application request' : 'outbound request through the confined workload'}. Check fresh AVCs, confinement and event delivery; silence alone is not success.")],
      rollback_steps: [step.call(prior_local ? "Restore the prior local singleton type" : "Remove only the newly created local singleton override", rollback,
        "Only after verifying this exact #{type} change was applied, no later owner/change intervened, and the prior state remains appropriate. Then recheck effective/local mappings and workload behavior.", "port_mapping")],
      rollback_description: prior_local ? "Modify back to the recorded existing local type #{prior_local[:type]}; do not delete that pre-existing mapping." : "Delete only this proposal's new singleton local record/override, restoring the recorded absence or base-range behavior. Never delete another record or a range.",
      persistence: "Persistent local SELinux port mapping; may reload policy. No application restart or firewall change is executed." }
    semantics = { boot_id: occurrence.host.current_snapshot&.details&.dig("boot_id"), current_policy_identity: fact.policy_identity,
      protocol: protocol, port: port, target_type: type, operation: investigation[:operation], object_class: @issue.target_class,
      prior_mappings: covering, prior_policy_records: ResolutionPlanBasis.ordered_set(policy_covering), action: action, policy_support: { query_kind: fact.query_kind, source_type: @issue.source_type,
        target_selector: "port_type", object_class: @issue.target_class, permission: investigation[:operation], evaluator_version: fact.evaluator_version,
        rules: ResolutionPlanBasis.ordered_set(option[:active_rules]) },
      booleans: Array(state["booleans"]).select { |boolean| booleans.include?(boolean["name"]) }.map { |boolean| boolean.slice("name", "status", "current") }.sort_by { |boolean| boolean["name"] } }
    { occurrence_id: occurrence.id, resource: [protocol, port, investigation[:operation], type], candidate: attributes, basis: basis, semantic_basis: semantics, plan: plan }
  end
end
