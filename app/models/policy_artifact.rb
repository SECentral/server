class PolicyArtifact < ApplicationRecord
  MAX_BYTES = 16 * 1024 * 1024
  IDENTITY_FORMAT = /\Asha256:[0-9a-f]{64}\z/

  validates :policy_identity, format: { with: IDENTITY_FORMAT }
  validates :artifact_size, numericality: { greater_than: 0, less_than_or_equal_to: MAX_BYTES }

  after_create_commit :enqueue_permissive_domain_analysis

  def enqueue_permissive_domain_analysis
    analysis = permissive_domain_analysis
    return unless analysis["status"].nil? || analysis["status"] == "pending"
    return if analysis["last_enqueued_at"] && Time.iso8601(analysis["last_enqueued_at"]) > PolicyFact::ENQUEUE_INTERVAL.ago

    enqueue = with_lock do
      analysis = permissive_domain_analysis
      next false unless analysis["status"].nil? || analysis["status"] == "pending"
      next false if analysis["last_enqueued_at"] && Time.iso8601(analysis["last_enqueued_at"]) > PolicyFact::ENQUEUE_INTERVAL.ago

      update_column(:permissive_domain_analysis, { "status" => "pending", "last_enqueued_at" => Time.current.iso8601(6) })
      true
    end
    AnalyzePolicyPermissiveDomainsJob.perform_later(id) if enqueue
  rescue StandardError => error
    Rails.logger.warn("permissive-domain analysis enqueue failed artifact=#{id}: #{error.message}")
  end
end
