class SelinuxExplanation
  def self.call(issue, intelligence: nil)
    new(issue, intelligence || IssueIntelligence.call(issue)).call
  end

  def initialize(issue, intelligence)
    @issue = issue
    @intelligence = intelligence
  end

  def call
    evaluation = @intelligence[:policy_evaluation] || PolicyEvaluation.call(@issue)
    occurrence_count = @issue.occurrences.count
    {
      what_happened: { source_type: @issue.source_type, target_type: @issue.target_type, target_class: @issue.target_class, permissions: @issue.permissions },
      observed_denial: { occurrences: occurrence_count, paths: @intelligence[:paths], contexts: @intelligence[:contexts] },
      policy_analysis: { status: evaluation[:status], limitations: evaluation[:limitations] },
      evaluated_mechanism: evaluation[:status] == "evaluated" ? evaluation : nil,
      potential_effect: { source_type: @issue.source_type, target_type: @issue.target_type, target_class: @issue.target_class, permissions: @issue.permissions },
      matching_observations: { count: occurrence_count, temporal_scope: "retained_issue_occurrences" },
      recommendation: { action: "investigate", text: "Review labels, constraints, transitions, and policy evidence before making any policy change." },
      confidence_band: evaluation[:status] == "evaluated" && evaluation[:limitations].empty? ? "medium" : "low",
      supporting_evidence: ["observed_denial", "issue_intelligence"],
      missing_evidence: evaluation[:limitations],
      limitations: ["Current evidence does not establish the policy state at AVC time.", "Matching observations are not resolved outcomes."],
      temporal_scope: "retained_issue_occurrences"
    }
  end
end
