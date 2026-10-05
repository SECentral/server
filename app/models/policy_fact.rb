class PolicyFact < ApplicationRecord
  QUERY_KIND = "allow"
  STATUSES = %w[pending matched no_match unavailable error].freeze
  ENQUEUE_INTERVAL = 1.minute

  validates :policy_identity, format: { with: PolicyArtifact::IDENTITY_FORMAT }
  validates :query_kind, inclusion: { in: [ QUERY_KIND ] }
  validates :source_type, :target_type, :object_class, :permission,
    format: { with: /\A[A-Za-z0-9_]+\z/ }
  validates :status, inclusion: { in: STATUSES }
  def enqueue_if_ready
    return unless status == "pending" && PolicyArtifact.exists?(policy_identity: policy_identity)

    enqueue = with_lock do
      next false unless status == "pending"
      next false if last_enqueued_at && last_enqueued_at > ENQUEUE_INTERVAL.ago

      update!(last_enqueued_at: Time.current)
      true
    end
    EvaluatePolicyFactJob.perform_later(id) if enqueue
  rescue StandardError => error
    update_column(:last_enqueued_at, nil) if enqueue
    Rails.logger.warn("policy fact enqueue failed id=#{id}: #{error.message}")
  end
end
