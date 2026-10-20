require "pathname"

class ResolutionWorkflow
  class EvidenceChanged < StandardError; end

  def initialize(issue, operator:, builder: nil)
    @issue, @operator = issue, operator
    @builder = builder || ResolutionCandidates.new(issue)
  end

  def call
    result = current_result
    intent = ResolutionIntent.find_by(issue: @issue, issue_signature_id: nil)
    active = intent && intent.status == "selected"
    candidate = active && result[:candidates].find { |c| c[:id] == intent.candidate_id }
    freshness, reasons = reviewed_freshness(active ? intent : nil, candidate)
    result.merge(candidates: result[:candidates].map { |item| item.except(:semantic_plan_basis) },
      intent: active ? intent.attributes.slice("candidate_id", "candidate_kind", "selected_intent", "operator", "selected_at", "evidence_version", "status") : nil,
      freshness: freshness, freshness_reasons: reasons, change_plan: freshness == "current" ? intent.plan_snapshot : nil,
      history: ResolutionIntentChange.where(issue: @issue).order(id: :desc).limit(25).map { |change| change.attributes.slice("action", "operator", "created_at", "details").merge("issue_signature_id" => change.issue_signature_id) })
  end

  def select!(id, version, home_content_review: nil)
    candidate = current_result[:candidates].find { |c| c[:id] == id }
    raise EvidenceChanged, "Candidate is no longer supported by current retained evidence" unless candidate && candidate[:status] == "proposed"
    raise EvidenceChanged, "Evidence changed; reload and review the candidate before selecting intent" unless candidate[:evidence_version] == version
    if candidate[:requires_home_content_review] && !valid_home_content_review?(candidate, home_content_review)
      raise EvidenceChanged, "Identify the complete file path, inspect current/configured labels and account/home configuration, and explicitly confirm intentional home-content access before selecting this Boolean."
    end
    basis = candidate[:evidence_basis]
    if candidate[:requires_home_content_review]
      basis = basis.merge(home_content_review: home_content_review.stringify_keys.slice("path", "confirmed").merge("host_id" => candidate[:host_id]))
    end

    @issue.with_lock do
      intent = ResolutionIntent.find_or_initialize_by(issue: @issue, issue_signature_id: nil)
      previous = intent.persisted? && intent.status == "selected" ? intent.candidate_id : nil
      intent.assign_attributes(candidate_id: id, candidate_kind: candidate[:kind], selected_intent: candidate[:intent_prompt],
        operator: @operator, selected_at: Time.current, status: "selected", evidence_basis: basis,
        evidence_version: version, semantic_plan_basis: candidate[:semantic_plan_basis],
        plan_semantics_version: candidate[:plan_semantics_version],
        plan_snapshot: @builder.plan(id).merge(evidence_version: version, evidence_basis: basis))
      intent.save!
      ResolutionIntentChange.create!(issue: @issue, operator: @operator, action: previous ? "changed" : "selected",
        details: { candidate_id: id, candidate_kind: candidate[:kind], selected_intent: candidate[:intent_prompt],
          previous_candidate_id: previous, evidence_version: version, evidence_basis: basis,
          plan_semantics_version: candidate[:plan_semantics_version] })
    end
    call
  end

  def clear!
    @issue.with_lock do
      intent = ResolutionIntent.find_by(issue: @issue, issue_signature_id: nil, status: "selected")
      if intent
        intent.update!(status: "cleared")
        ResolutionIntentChange.create!(issue: @issue, operator: @operator, action: "cleared",
          details: { candidate_id: intent.candidate_id, evidence_version: intent.evidence_version })
      end
    end
    call
  end

  private

  def valid_home_content_review?(candidate, review)
    return false unless review.is_a?(Hash)

    review = review.stringify_keys
    path = review["path"]
    return false unless review["confirmed"] == true && path.is_a?(String) && path != "/" && path.bytesize <= 4096 && path.start_with?("/") && !path.match?(/[\0\r\n]/) && Pathname.new(path).cleanpath.to_s == path
    return false if candidate[:home_content_path].present? && path != candidate[:home_content_path]

    names = Array(candidate.dig(:evidence_basis, :home_content_names)).map { |name| File.basename(name) }.uniq
    names.empty? || names == [File.basename(path)]
  end

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

  # Reviewed-plan freshness and explicit operator attestations are enforced here.
  def reviewed_freshness(intent, candidate)
    return [nil, []] unless intent
    unless candidate && candidate[:status] != "no_longer_supported"
      reason = candidate&.dig(:unavailable_reason)
      reason ||= if intent.candidate_kind == "restore_configured_label"
        "The selected host/path no longer has an eligible configured-label mismatch. Review its retained path and latest expected-context observations for missing, agreeing or conflicting context evidence."
      elsif intent.candidate_kind == "set_port_mapping"
        "The selected port mapping no longer meets its policy, current mapping or conflict prerequisites. Check the selected host/protocol/port investigation; no stale mapping commands are exposed."
      else
        "The selected host no longer has an eligible inactive positive conditional path with observed Off state. Review its policy and Boolean evidence."
      end
      return ["no_longer_supported", [reason]]
    end
    return ["evidence_changed", [candidate[:unavailable_reason] || "Current retained evidence is not sufficiently fresh for this candidate."]] unless candidate[:status] == "proposed"
    if candidate[:requires_home_content_review] && !valid_home_content_review?(candidate, intent.evidence_basis["home_content_review"])
      return ["evidence_changed", ["This Boolean review needs explicit confirmation of the identified file, labeling checks and intentional home-content access on this host."]]
    end
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
