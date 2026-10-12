class AnalyzePolicyPermissiveDomainsJob < ApplicationJob
  queue_as :default

  def perform(artifact_id, semantics_version = PolicyPermissiveDomainAnalyzer::SEMANTICS_VERSION)
    return unless semantics_version == PolicyPermissiveDomainAnalyzer::SEMANTICS_VERSION

    artifact = PolicyArtifact.find_by(id: artifact_id)
    return unless artifact

    artifact.with_lock do
      analysis = artifact.permissive_domain_analysis
      return if analysis["semantics_version"] && analysis["semantics_version"] != semantics_version
      return unless analysis["status"].nil? || analysis["status"] == "pending"

      result = PolicyPermissiveDomainAnalyzer.call(artifact)
      return unless semantics_version == PolicyPermissiveDomainAnalyzer::SEMANTICS_VERSION

      artifact.update_column(:permissive_domain_analysis, result.merge("evaluated_at" => Time.current.iso8601(6),
        "semantics_version" => semantics_version, "policy_identity" => artifact.policy_identity))
    end
  end
end
