class PolicyFactRequest
  TYPE_FORMAT = /\A[A-Za-z0-9_]+\z/
  KEY_FIELDS = %i[policy_identity query_kind source_type target_type object_class permission].freeze

  def self.for_event(raw_event)
    for_events([ raw_event ])
  end

  def self.for_events(raw_events)
    questions = raw_events.flat_map do |raw_event|
      identity = raw_event.checkpoint_policy_identity
      questions_for(raw_event.normalized_denials.select { |denial| denial.status == "ok" }, identity)
    end
    persist(questions)
  end

  def self.for_issue(issue)
    questions = issue.occurrences.includes(:host_snapshot, :normalized_denial, :raw_event).flat_map do |occurrence|
      denial = occurrence.normalized_denial
      next [] unless occurrence.host_snapshot && denial&.status == "ok"

      identity = occurrence.policy_identity
      questions_for([ denial ], identity)
    end
    persist(questions)
  end

  def self.for_current_issue_hosts(issue)
    denials = issue.occurrences.includes(:normalized_denial).map(&:normalized_denial).compact
    questions = Host.where(id: issue.occurrences.select(:host_id)).includes(current_state_observation: :host_snapshot).flat_map do |host|
      questions_for(denials.first(1), host.current_policy_identity)
    end
    persist(questions)
  end

  def self.questions_for(denials, identity)
    return [] unless identity.to_s.match?(PolicyArtifact::IDENTITY_FORMAT)

    denials.flat_map do |denial|
      Array(denial.permissions).uniq.filter_map do |permission|
        fields = {
          policy_identity: identity, query_kind: PolicyFact::QUERY_KIND,
          source_type: denial.source_type, target_type: denial.target_type,
          object_class: denial.target_class, permission: permission
        }
        fields if fields.values_at(:source_type, :target_type, :object_class, :permission).all? { |value| value.to_s.match?(TYPE_FORMAT) }
      end
    end
  end
  private_class_method :questions_for

  def self.persist(questions)
    questions = questions.uniq { |question| question.values_at(*KEY_FIELDS) }
    return if questions.empty?

    now = Time.current
    PolicyFact.insert_all(questions.map { |question| question.merge(status: "pending", matching_rules: [], rule_details: [], created_at: now, updated_at: now) },
      unique_by: "index_policy_facts_on_exact_question")
    keys = questions.to_h { |question| [ question.values_at(*KEY_FIELDS), true ] }
    PolicyFact.where(policy_identity: questions.map { |question| question[:policy_identity] }.uniq, status: "pending").find_each do |fact|
      key = fact.attributes.symbolize_keys.values_at(*KEY_FIELDS)
      fact.enqueue_if_ready if keys.key?(key)
    end
  end
  private_class_method :persist
end
