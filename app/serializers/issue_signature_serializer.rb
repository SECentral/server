class IssueSignatureSerializer
  def self.call(signature)
    signature.attributes.slice("id", "fingerprint_version", "fingerprint_digest", "permissions", "status", "disposition",
      "first_seen_at", "last_seen_at", "resolved_at", "ignored_at", "reopened_at", "regressions_count").merge(
        "legacy" => signature.fingerprint_version != 3,
        "occurrences_count" => signature.occurrences.size,
        "affected_hosts" => signature.occurrences.map(&:host_id).uniq.size)
  end
end
