class Api::V1::IssuesController < Api::V1::BaseController
  def index
    query = IssueQuery.new(
      filters: params.permit(IssueQuery::FILTER_KEYS.map(&:to_sym)).to_h,
      host_id: params[:host_id].presence,
      page: params[:page], limit: params[:limit]
    ).call
    hosts = Host.includes(current_state_observation: :host_snapshot).order(:hostname, :external_id).to_a
    enforcing = hosts.count { |host| enforcing?(host) }

    render json: {
      issues: query.issues.map { |issue| IssueListSerializer.call(issue) },
      host_options: hosts.map { |host| { id: host.id, hostname: host.hostname } },
      meta: {
        page: query.page,
        page_size: query.page_size,
        total: query.total_count,
        total_pages: (query.total_count / query.page_size.to_f).ceil
      },
      summary: {
        total_count: query.total_count,
        open_count: Issue.where(status: "open").count,
        regressed_count: Issue.where(status: "open").where.not(reopened_at: nil)
          .where("resolved_at IS NULL OR reopened_at > resolved_at").count,
        ungroupable_count: ungroupable_count,
        monitored_hosts: hosts.size,
        enforcing_hosts: enforcing,
        enforcement_percent: hosts.empty? ? 0 : (enforcing * 100.0 / hosts.size).round
      }
    }
  end

  def show
    issue = current_organization.issues.find(params[:id])
    intelligence = IssueIntelligence.call(issue, include_analysis: false)
    analyzer = IssueDiagnosis.new(issue, intelligence)
    host_explanations = analyzer.per_host
    findings = analyzer.finding_summaries
    displayed_findings = findings.uniq { |finding| finding[:diagnosis][:kind] }.first(3)
    fleet_explanation = FleetExplanation.call(host_explanations)
    finding_counts = host_explanations.flat_map { |host| host[:occurrence_diagnoses] }
      .flat_map { |item| item[:findings].empty? ? [ "unexplained" ] : item[:findings].map { |finding| finding[:kind] } }.tally
    host_explanations = host_explanations.map { |host| issue_host_explanation(host) }
    summary = intelligence.slice(:affected_hosts, :occurrence_time, :resource_summary, :observation_summary)
    summary[:paths] = intelligence[:paths].first(3)
    summary[:names] = intelligence[:names].first(3)
    summary[:resource_summary].merge!(path_count: intelligence[:paths].size, name_count: intelligence[:names].size,
      process_command: intelligence[:commands].one? ? intelligence[:commands].first : nil)
    summary[:fleet] = intelligence[:fleet].slice(:activity_hosts, :current_configuration_hosts, :hosts_with_occurrence, :hosts_without_occurrence, :comparison_requirement)
    diagnosis = displayed_findings.first&.fetch(:diagnosis)
    investigation = IssueInvestigation.call(issue, analyzer: analyzer)
    render json: {
      issue: IssueDetailSerializer.call(issue),
      related_activity: RelatedIssueActivity.call(issue),
      intelligence: summary,
      finding_coverage: finding_counts,
      supported_occurrence_count: issue.occurrences.count - finding_counts.fetch("unexplained", 0),
      findings: displayed_findings,
      additional_finding_count: findings.size - displayed_findings.size,
      diagnosis: diagnosis,
      triage_guidance: investigation[:triage_guidance],
      operator_guidance: investigation[:operator_guidance],
      host_explanations: host_explanations,
      fleet_explanation: fleet_explanation.slice(:state, :affected_host_count, :host_status_counts),
      policy_analysis: intelligence[:policy_evaluation].slice(:status, :limitations, :occurrence_counts),
      resolutions: ResolutionWorkflow.new(issue, operator: session[:operator_username],
        builder: ResolutionCandidates.new(issue, intelligence: intelligence, analyzer: analyzer)).call,
      triage: IssueTriageSignals.call(issue)
    }
  end

  def update_status
    issue = current_organization.issues.find(params[:id])
    issue.transition_to!(params.require(:status), signature_ids: params.require(:signature_ids))
    render json: IssueDetailSerializer.call(issue.reload)
  rescue ArgumentError
    render json: { error: { code: "invalid_value", message: "Unknown status or invalid reviewed signatures" } }, status: :unprocessable_content
  end

  def update_disposition
    issue = current_organization.issues.find(params[:id])
    issue.set_disposition!(params.require(:disposition), note: params[:note], signature_ids: params.require(:signature_ids))
    render json: IssueDetailSerializer.call(issue.reload)
  rescue ArgumentError
    render json: { error: { code: "invalid_value", message: "Unknown disposition or invalid reviewed signatures" } }, status: :unprocessable_content
  end

  private

  def issue_host_explanation(host)
    groups = host[:occurrence_diagnoses].group_by { |occurrence| occurrence[:agreement_signature] }.values
    displayed_groups = groups.first(5).map do |occurrences|
      occurrence = occurrences.first
      policy_provenance = occurrences.flat_map do |item|
        item[:findings].filter_map do |finding|
          next unless finding[:policy_identity]

          { policy_identity: finding[:policy_identity], checkpoint_observed_at: finding[:checkpoint_observed_at], occurrence_id: item[:occurrence_id] }
        end
      end.uniq { |item| item[:policy_identity] }
      displayed_provenance = policy_provenance.first(5)
      { status: occurrence[:diagnosis] ? "diagnosed" : "insufficient_evidence", count: occurrences.size,
        diagnosis: occurrence[:diagnosis], findings: occurrence[:findings], sample_occurrence_ids: occurrences.first(3).map { |item| item[:occurrence_id] },
        policy_identity_count: policy_provenance.size, policy_provenance: displayed_provenance,
        additional_policy_identity_count: [ policy_provenance.size - displayed_provenance.size, 0 ].max }
    end

    # ponytail: cap variants at five with three occurrence examples and five policy identities each; inspect occurrences for the rest.
    host.slice(:host_id, :hostname, :status, :diagnosis).merge(
      occurrence_count: host[:occurrence_diagnoses].size,
      unexplained_occurrence_count: host[:occurrence_diagnoses].count { |item| item[:diagnosis].nil? },
      diagnosis_groups: displayed_groups,
      additional_diagnosis_group_count: [ groups.size - displayed_groups.size, 0 ].max
    )
  end

  def enforcing?(host)
    host.current_configuration? && host.enforcement_for == "enforcing"
  end

  def ungroupable_count
    scope = Occurrence.joins(:normalized_denial).where(normalized_denials: { status: "ungroupable" })
    scope = scope.where(host_id: params[:host_id].presence) if params[:host_id].present?
    scope.count
  end
end
