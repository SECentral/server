class PolicyEvaluation
  def self.call(issue)
    new(issue).call
  end

  def initialize(issue)
    @issue = issue
  end

  def call
    request_policy_facts
    occurrences = @issue.occurrences
    occurrences = occurrences.includes(:host_snapshot, :normalized_denial, :raw_event) if occurrences.respond_to?(:includes)
    facts = policy_facts(occurrences)
    occurrence_evaluations = occurrences.map do |occurrence|
      evaluate_occurrence(occurrence, facts)
    end
    completed = occurrence_evaluations.select { |item| item[:status] == "evaluated" }
    facts = occurrence_evaluations.flat_map { |item| item[:evaluations] }
    identities = occurrence_evaluations.flat_map { |item| Array(item[:policy_identity]) }.uniq
    limitations = occurrence_evaluations.flat_map { |item| Array(item[:limitations]) }.uniq
    active_count = occurrence_evaluations.count { |item| item[:rule_state] == "conditional_active" }
    if active_count.positive?
      limitations << "For #{active_count} #{"denial".pluralize(active_count)}, a matching conditional rule was active at the associated checkpoint, so that sample does not support an inactive-condition explanation. Checkpoint state is not an AVC-time measurement."
    end
    status = if completed.any?
      "evaluated"
    elsif occurrence_evaluations.any? { |item| item[:status] == "pending" }
      "pending"
    elsif occurrence_evaluations.any? { |item| item[:status] == "error" }
      "error"
    else
      "unavailable"
    end
    limitations << "no exact reusable policy facts are available" if limitations.empty? && status != "evaluated"
    {
      status: status,
      policy_identity: identities.one? ? identities.first : nil,
      evaluator_version: facts.map { |fact| fact["evaluator_version"] }.compact.uniq.first,
      result: facts.map { |fact| fact["result"] }.uniq,
      observed_permissions: facts.flat_map { |fact| fact["permissions"] }.uniq,
      matching_rules: facts.flat_map { |fact| fact["matching_rules"] }.uniq,
      technical_evaluations: facts,
      booleans: occurrence_evaluations.flat_map { |item| item[:booleans] }.uniq,
      conditional_booleans: conditional_boolean_names(facts),
      conditional_expressions: facts.flat_map { |fact| conditional_expressions(fact) }.uniq,
      conditional_rule_states: occurrence_evaluations.flat_map { |item| item[:conditional_rule_states] }.uniq,
      limitations: limitations,
      occurrence_evaluations: occurrence_evaluations
    }
  end

  private

  def request_policy_facts
    RequestPolicyFactsJob.perform_later(issue_id: @issue.id) if @issue.respond_to?(:id) && @issue.id
  rescue StandardError => error
    Rails.logger.warn("policy fact request enqueue failed: #{error.message}")
  end

  def policy_facts(occurrences)
    identities = occurrences.filter_map do |occurrence|
      identity = occurrence.raw_event&.checkpoint_policy_identity(occurrence.host_snapshot)
      identity if identity.to_s.match?(PolicyArtifact::IDENTITY_FORMAT)
    end.uniq
    return {} if identities.empty?

    PolicyFact.where(
      policy_identity: identities, query_kind: PolicyFact::QUERY_KIND,
      source_type: @issue.source_type, target_type: @issue.target_type,
      object_class: @issue.target_class, permission: Array(@issue.permissions).uniq
    ).index_by { |fact| [ fact.policy_identity, fact.permission ] }
  end

  def evaluate_occurrence(occurrence, facts_by_key)
    # Reuse rule/boolean work for the same immutable snapshot and denial inputs,
    # but attach each event's own checkpoint timestamp and identity afterwards.
    @policy_contexts ||= {}
    denial = occurrence.normalized_denial
    key = [ occurrence.host_snapshot&.object_id, (Array(occurrence.raw_event&.checkpoint_invalidated_fields) & %w[policy_identity booleans]).sort, Array(denial&.permissions).uniq.sort,
      denial&.details.to_h.fetch("enforcement_mode", "unknown") ]
    context = @policy_contexts[key] ||= evaluate_policy_context(occurrence, facts_by_key)
      .except(:occurrence_id, :host_id, :checkpoint_observed_at)
    context.merge(occurrence_id: occurrence.id, host_id: occurrence.host_id,
      checkpoint_observed_at: occurrence.raw_event&.host_observed_at,
      checkpoint_enforcement_mode: occurrence.raw_event&.checkpoint_enforcement_mode(occurrence.host_snapshot) || "unknown")
  end

  def evaluate_policy_context(occurrence, facts_by_key)
    denial = occurrence.normalized_denial
    identity = occurrence.raw_event&.checkpoint_policy_identity(occurrence.host_snapshot)
    return unavailable_occurrence(occurrence, "exact policy identity is unavailable") unless identity.to_s.match?(PolicyArtifact::IDENTITY_FORMAT)

    permissions = Array(denial&.permissions).uniq
    return unavailable_occurrence(occurrence, "denied permission is unavailable", identity) if permissions.empty?

    facts = permissions.filter_map { |permission| facts_by_key[[ identity, permission ]] }
    evaluations = facts.select { |fact| %w[matched no_match].include?(fact.status) }.map { |fact| serialize_fact(fact) }
    boolean_names = conditional_boolean_names(evaluations)
    booleans = checkpoint_booleans(occurrence).select { |boolean| boolean_names.include?(boolean["name"]) }
    questions = permissions.map do |permission|
      fact = facts.find { |value| value.permission == permission }
      { permission: permission, status: fact&.status || "pending", error: fact&.error_message }
    end
    state = if questions.all? { |question| question[:status] == "no_match" }
      "no_matching_allow"
    elsif evaluations.any? { |fact| fact["result"] == "matched" }
      conditional_state(evaluations, booleans)
    elsif questions.any? { |question| question[:status] == "pending" }
      "pending"
    else
      "unknown"
    end
    status = if questions.all? { |question| %w[matched no_match].include?(question[:status]) }
      "evaluated"
    elsif questions.any? { |question| question[:status] == "pending" }
      "pending"
    elsif questions.any? { |question| question[:status] == "error" }
      "error"
    else
      "unavailable"
    end
    {
      status: status,
      occurrence_id: occurrence.id,
      host_id: occurrence.host_id,
      policy_identity: [ identity ],
      checkpoint_observed_at: occurrence.raw_event&.host_observed_at,
      evaluations: evaluations,
      policy_questions: questions,
      rule_state: state,
      enforcement_mode: denial.details.to_h.fetch("enforcement_mode", "unknown"),
      permissive: denial.details.to_h.fetch("enforcement_mode", "unknown") == "permissive" ? true : denial.details.to_h.fetch("enforcement_mode", "unknown") == "enforcing" ? false : nil,
      booleans: booleans,
      conditional_booleans: boolean_names,
      conditional_rule_states: conditional_rule_states(evaluations, booleans),
      limitations: questions.filter_map { |question| question[:error] || ("policy fact #{question[:permission]} is #{question[:status]}" unless %w[matched no_match].include?(question[:status])) }
    }
  end

  def serialize_fact(fact)
    {
      "policy_fact_id" => fact.id,
      "policy_identity" => fact.policy_identity,
      "evaluator_version" => fact.evaluator_version,
      "result" => fact.status,
      "source_type" => fact.source_type,
      "target_type" => fact.target_type,
      "target_class" => fact.object_class,
      "permissions" => [ fact.permission ],
      "matching_rules" => fact.matching_rules,
      "rule_details" => fact.rule_details,
      "provenance" => "setools_exact_policy_artifact"
    }
  end

  def unavailable_occurrence(occurrence, reason, identity = nil)
    mode = occurrence.normalized_denial&.details.to_h.fetch("enforcement_mode", "unknown")
    {
      status: "unavailable", occurrence_id: occurrence.id, host_id: occurrence.host_id,
      policy_identity: identity ? [ identity ] : [], evaluations: [], policy_questions: [],
      rule_state: "unknown", enforcement_mode: mode, permissive: mode == "permissive" ? true : mode == "enforcing" ? false : nil,
      booleans: [], conditional_booleans: [],
      conditional_rule_states: [], limitations: [ reason ]
    }
  end

  def checkpoint_booleans(occurrence)
    occurrence.raw_event&.checkpoint_trust(occurrence.host_snapshot)&.booleans || []
  end

  def conditional_state(facts, booleans)
    states = conditional_rule_states(facts, booleans)
    return "unconditional_match" if states.empty?
    return "conditional_active" if states.any? { |rule| rule[:state] == "active" }
    return "unknown" if states.any? { |rule| rule[:state] == "unknown" }

    "conditional_inactive"
  end

  def conditional_rule_states(facts, booleans)
    values = booleans.to_h do |boolean|
      value = boolean["current"] if boolean["status"] == "observed" && [ true, false ].include?(boolean["current"])
      [ boolean["name"], value ]
    end
    facts.flat_map do |fact|
      conditional_expressions(fact).filter_map do |rule|
        expression = rule[/\[([^\]]+)\]/, 1]&.strip
        branch = rule[/\]:\s*(True|False)\z/, 1]
        next unless expression

        active = BooleanExpression.call(expression, values)
        active = !active if branch == "False" && !active.nil?
        { expression: expression, rule: rule, branch: branch, state: active.nil? ? "unknown" : active ? "active" : "inactive" }
      end
    end.uniq
  end

  def conditional_expressions(fact)
    Array(fact["matching_rules"]).select { |rule| rule.include?("[") }
  end

  def conditional_boolean_names(facts)
    facts.flat_map do |fact|
      conditional_expressions(fact).flat_map do |rule|
        rule.scan(/\[([^\]]+)\]/).flat_map { |expression| expression.first.scan(/[A-Za-z0-9_]+/) }
      end
    end.reject { |name| %w[True False].include?(name) }.uniq
  end

  class BooleanExpression
    def self.call(expression, values)
      new(expression, values).call
    end

    def initialize(expression, values)
      @tokens = expression.scan(/&&|\|\||!|\(|\)|[A-Za-z0-9_]+/)
      @values = values
      @position = 0
    end

    def call
      value = parse_or
      value unless @position != @tokens.length
    rescue StandardError
      nil
    end

    private

    def parse_or
      value = parse_and
      while token("||")
        value = combine(value, parse_and, :or)
      end
      value
    end

    def parse_and
      value = parse_not
      while token("&&")
        value = combine(value, parse_not, :and)
      end
      value
    end

    def parse_not
      return !parse_not if token("!")
      if token("(")
        value = parse_or
        raise "missing closing parenthesis" unless token(")")
        return value
      end

      name = @tokens.fetch(@position)
      @position += 1
      @values.fetch(name)
    end

    def token(value)
      return false unless @tokens[@position] == value

      @position += 1
      true
    end

    def combine(left, right, operator)
      return nil if left.nil? || right.nil?

      operator == :and ? left && right : left || right
    end
  end
end
