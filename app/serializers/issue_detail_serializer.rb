class IssueDetailSerializer
  def self.call(issue)
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
      occurrences_count: issue.occurrences_count,
      affected_hosts: issue.occurrences.distinct.count(:host_id),
      disposition_history: issue.disposition_changes.order(created_at: :desc).limit(20).map do |change|
        { disposition: change.disposition, previous_disposition: change.previous_disposition, note: change.note, changed_at: change.created_at }
      end
    }
  end
end
