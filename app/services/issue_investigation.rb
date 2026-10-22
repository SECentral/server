require "pathname"

class IssueInvestigation
  def self.call(issue, analyzer:)
    occurrences = issue.occurrences.includes(:host, :normalized_denial).order(occurred_at: :desc, id: :desc).to_a
    findings = analyzer.finding_summaries.map { |item| item.fetch(:diagnosis) }
    filesystem = %w[file dir lnk_file fifo_file chr_file blk_file sock_file].include?(issue.target_class)
    mismatch = findings.find { |finding| finding[:kind] == "file_context_mismatch" }
    occurrence = occurrences.find { |item| item.id == mismatch&.dig(:occurrence_id) && absolute_paths(item).include?(mismatch[:path]) }
    occurrence ||= occurrences.reverse.find { |item| absolute_paths(item).one? } if filesystem
    occurrence ||= occurrences.find { |item| item.id == findings.first&.dig(:occurrence_id) } || occurrences.first
    return {} unless occurrence

    diagnosis = findings.find { |finding| finding[:occurrence_id] == occurrence.id }
    observations = analyzer.eligible_expected_context_observations.select do |item|
      item[:host_id] == occurrence.host_id && item[:occurrence_id] == occurrence.id
    end
    triage = if diagnosis&.dig(:kind) != "file_context_mismatch" && absolute_paths(occurrence).one?
      IssueLabelingGuidance.call(issue, paths: absolute_paths(occurrence), observations: observations)
    end
    triage = triage.merge(host_id: occurrence.host_id, occurrence_id: occurrence.id) if triage
    { triage_guidance: triage,
      operator_guidance: IssueOperatorGuidance.call(issue, diagnosis: diagnosis, triage_guidance: triage, occurrence: occurrence) }
  end

  def self.absolute_paths(occurrence)
    Array(occurrence.normalized_denial.details.dig("target_evidence", "filesystem_paths"))
      .select { |path| path.is_a?(String) && path.start_with?("/") && !path.match?(/[\0\r\n]/) && Pathname.new(path).cleanpath.to_s == path }.uniq
  end
  private_class_method :absolute_paths
end
