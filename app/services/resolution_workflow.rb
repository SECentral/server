class ResolutionWorkflow
  class EvidenceChanged < StandardError; end

  def initialize(issue, operator:, builder: nil)
    @issue, @operator = issue, operator
    @builder = builder || ResolutionCandidates.new(issue)
  end

  def call
    result = current_result
    intent = ResolutionIntent.find_by(issue: @issue)
    active = intent && intent.status == "selected"
    candidate = active && result[:candidates].find { |c| c[:id] == intent.candidate_id }
    freshness, reasons = reviewed_freshness(active ? intent : nil, candidate)
    result.merge(candidates: result[:candidates].map { |item| item.except(:semantic_plan_basis) },
      intent: active ? intent.attributes.slice("candidate_id", "candidate_kind", "selected_intent", "operator", "selected_at", "evidence_version", "status") : nil,
      freshness: freshness, freshness_reasons: reasons, change_plan: freshness == "current" ? intent.plan_snapshot : nil,
      history: ResolutionIntentChange.where(issue: @issue).order(id: :desc).limit(25).map { |change| change.attributes.slice("action", "operator", "created_at", "details") })
  end

  def select!(id, version)
    candidate = current_result[:candidates].find { |c| c[:id] == id }
    raise EvidenceChanged, "Candidate is no longer supported by current retained evidence" unless candidate && candidate[:status] == "proposed"
    raise EvidenceChanged, "Evidence changed; reload and review the candidate before selecting intent" unless candidate[:evidence_version] == version

    @issue.with_lock do
      intent = ResolutionIntent.find_or_initialize_by(issue: @issue)
      previous = intent.persisted? && intent.status == "selected" ? intent.candidate_id : nil
      intent.assign_attributes(candidate_id: id, candidate_kind: candidate[:kind], selected_intent: candidate[:intent_prompt],
        operator: @operator, selected_at: Time.current, status: "selected", evidence_basis: candidate[:evidence_basis],
        evidence_version: version, semantic_plan_basis: candidate[:semantic_plan_basis],
        plan_semantics_version: candidate[:plan_semantics_version],
        plan_snapshot: @builder.plan(id).merge(evidence_version: version))
      intent.save!
      ResolutionIntentChange.create!(issue: @issue, operator: @operator, action: previous ? "changed" : "selected",
        details: { candidate_id: id, candidate_kind: candidate[:kind], selected_intent: candidate[:intent_prompt],
          previous_candidate_id: previous, evidence_version: version, evidence_basis: candidate[:evidence_basis],
          plan_semantics_version: candidate[:plan_semantics_version] })
    end
    call
  end

  def clear!
    @issue.with_lock do
      intent = ResolutionIntent.find_by(issue: @issue, status: "selected")
      if intent
        intent.update!(status: "cleared")
        ResolutionIntentChange.create!(issue: @issue, operator: @operator, action: "cleared",
          details: { candidate_id: intent.candidate_id, evidence_version: intent.evidence_version })
      end
    end
    call
  end

  private

  def current_result
    @current_result ||= @builder.call.then do |result|
      result.merge(candidates: result[:candidates].map do |candidate|
        candidate.merge(evidence_version: semantic_digest(candidate))
      end)
    end
  end

  def semantic_digest(candidate)
    ResolutionPlanBasis.digest(format_version: ResolutionPlanBasis::FORMAT_VERSION,
      candidate_id: candidate[:id], candidate_kind: candidate[:kind],
      plan_semantics_version: candidate[:plan_semantics_version], semantic_plan_basis: candidate[:semantic_plan_basis])
  end

  # The sole reviewed-plan decision owner. No SELinux field-specific comparisons.
  def reviewed_freshness(intent, candidate)
    return [nil, []] unless intent
    return ["no_longer_supported", ["The selected candidate is no longer supported by current retained evidence."]] unless candidate && candidate[:status] != "no_longer_supported"
    return ["evidence_changed", ["Current retained evidence is not sufficiently fresh for this candidate."]] unless candidate[:status] == "proposed"
    unless intent.semantic_plan_basis.is_a?(Hash) && intent.semantic_plan_basis.present? && intent.plan_semantics_version.present?
      return ["evidence_changed", ["This review predates the semantic freshness model; review the current evidence once."]]
    end
    if intent.plan_semantics_version != candidate[:plan_semantics_version]
      return ["evidence_changed", ["Plan-generation semantics changed since this plan was reviewed."]]
    end
    if intent.candidate_kind != candidate[:kind] || intent.evidence_version != candidate[:evidence_version] ||
        ResolutionPlanBasis.canonical(intent.semantic_plan_basis) != ResolutionPlanBasis.canonical(candidate[:semantic_plan_basis])
      return ["evidence_changed", ["Candidate-relevant evidence, scope or safety assumptions changed since review."]]
    end
    ["current", []]
  end
end
