# Exact-artifact knowledge only. Callers supply an effective trusted identity,
# never recover an identity from a masked checkpoint or module names.
class PolicyPermissiveDomains
  def self.for_identities(identities)
    valid = identities.compact.uniq.select { |identity| identity.match?(PolicyArtifact::IDENTITY_FORMAT) }
    PolicyArtifact.where(policy_identity: valid).select(:id, :policy_identity, :permissive_domain_analysis).to_h do |artifact|
      analysis = artifact.permissive_domain_analysis
      artifact.enqueue_permissive_domain_analysis if analysis["status"].nil? || analysis["status"] == "pending"
      [artifact.policy_identity, {
        status: analysis.fetch("status", "pending"), policy_identity: artifact.policy_identity,
        domains: analysis["status"] == "observed" ? analysis.fetch("domains") : nil,
        provenance: "exact_loaded_policy_artifact", evaluator_version: analysis["evaluator_version"],
        evaluated_at: analysis["evaluated_at"], reason: analysis["error_message"]
      }]
    end
  end

  def self.lookup(identity, facts = nil)
    return { status: "unavailable", policy_identity: nil, domains: nil, provenance: "exact_loaded_policy_artifact", reason: "Trusted exact policy identity is unavailable" } unless identity.to_s.match?(PolicyArtifact::IDENTITY_FORMAT)

    (facts || for_identities([identity])).fetch(identity) {
      { status: "unavailable", policy_identity: identity, domains: nil, provenance: "exact_loaded_policy_artifact", reason: "Exact policy artifact is unavailable" }
    }
  end

  def self.for_occurrence(occurrence, facts = nil)
    raw = occurrence.raw_event
    state = lookup(raw.checkpoint_policy_identity(occurrence.host_snapshot), facts)
    source = occurrence.normalized_denial.source_type
    member = state[:domains]&.include?(source) unless source.nil?
    local = occurrence.normalized_denial.details["permissive"]
    mode = raw.checkpoint_enforcement_mode(occurrence.host_snapshot)
    consistency = if member.nil? || ![true, false].include?(local)
      "unavailable"
    elsif member && !local || !member && local && mode == "enforcing"
      "diagnostic_mismatch"
    elsif !member && local
      "global_mode_may_explain"
    else
      "consistent"
    end
    state.except(:domains).merge(source_type: source, source_domain_permissive: member, avc_policy_consistency: consistency)
  end

  def self.compare(from, to)
    facts = for_identities([from, to])
    before, after = lookup(from, facts), lookup(to, facts)
    return unless before[:status] == "observed" && after[:status] == "observed"

    { evidence_class: "derived_exact_policy_comparison", from_policy_identity: from, to_policy_identity: to,
      added: after[:domains] - before[:domains], removed: before[:domains] - after[:domains] }
  end
end
