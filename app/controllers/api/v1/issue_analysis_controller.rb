class Api::V1::IssueAnalysisController < Api::V1::BaseController
  def show
    issue = Issue.find(params[:id])
    intelligence = IssueIntelligence.call(issue)
    triage = IssueTriageSignals.call(issue)
    host_explanations = IssueDiagnosis.per_host(issue, intelligence: intelligence)
    render json: {
      host_explanations: host_explanations,
      fleet_explanation: FleetExplanation.call(host_explanations),
      hypotheses: IssueHypotheses.call(issue, intelligence: intelligence, triage: triage),
      supporting_evidence: {
        explanation: intelligence[:explanation],
        file_contexts: intelligence.slice(:event_file_contexts, :expected_context_observations, :correlated_file_contexts, :current_file_context_matches, :configuration_drift)
      }
    }
  end
end
