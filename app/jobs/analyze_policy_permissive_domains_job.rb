class AnalyzePolicyPermissiveDomainsJob < ApplicationJob
  queue_as :default

  def perform(artifact_id)
    artifact = PolicyArtifact.find_by(id: artifact_id)
    return unless artifact

    artifact.with_lock do
      return unless artifact.permissive_domain_analysis["status"].nil? || artifact.permissive_domain_analysis["status"] == "pending"

      result = PolicyPermissiveDomainAnalyzer.call(artifact)
      artifact.update_column(:permissive_domain_analysis, result.merge("evaluated_at" => Time.current.iso8601(6)))
    end
  end
end
