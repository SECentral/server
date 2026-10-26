class IssueListSerializer
  def self.call(issue)
    occurrences = issue.occurrences.to_a
    hosts = occurrences.filter_map(&:host).uniq(&:id).sort_by { |host| [host.hostname.to_s, host.id] }
    paths = occurrences.filter_map { |occurrence| occurrence.normalized_denial&.target_paths }.flatten.uniq.sort
    {
      id: issue.id,
      status: issue.status,
      display_status: issue.display_status,
      disposition: issue.disposition,
      source_type: issue.source_type,
      target_type: issue.target_type,
      target_class: issue.target_class,
      permissions: issue.permissions,
      signatures_count: occurrences.filter_map(&:issue_signature_id).uniq.size,
      fingerprint_version: issue.fingerprint_version,
      fingerprint_digest: issue.fingerprint_digest,
      first_seen_at: issue.first_seen_at,
      last_seen_at: issue.last_seen_at,
      occurrences_count: occurrences.size,
      hosts_count: hosts.size,
      hosts: hosts.map { |host| { id: host.id, hostname: host.hostname } },
      observed_paths: paths,
      observations: ObservationSummary.from_rows(occurrences.map { |item| [item.raw_event_id, item.normalized_denial.details] })
    }
  end
end
