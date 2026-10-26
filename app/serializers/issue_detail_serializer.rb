class IssueDetailSerializer
  def self.call(issue)
    observations = ObservationSummary.call(issue.occurrences)
    {
      id: issue.id,
      organization_id: issue.organization_id,
      status: issue.status,
      display_status: issue.display_status,
      disposition: issue.disposition,
      resolved_at: issue.resolved_at,
      ignored_at: issue.ignored_at,
      reopened_at: issue.reopened_at,
      regressions_count: issue.regressions_count,
      fingerprint_version: issue.fingerprint_version,
      fingerprint_digest: issue.fingerprint_digest,
      source_type: issue.source_type,
      target_type: issue.target_type,
      target_class: issue.target_class,
      permissions: issue.permissions,
      first_seen_at: issue.first_seen_at,
      last_seen_at: issue.last_seen_at,
      occurrences_count: observations[:occurrences],
      observations: observations,
      affected_hosts: issue.occurrences.distinct.count(:host_id),
      signatures: issue.active_signatures.includes(:occurrences).order(:id).map { |signature| IssueSignatureSerializer.call(signature) },
      disposition_history: issue.disposition_changes.order(created_at: :desc).limit(20).map do |change|
        { disposition: change.disposition, previous_disposition: change.previous_disposition, note: change.note, changed_at: change.created_at, issue_signature_id: change.issue_signature_id }
      end
    }
  end
end
