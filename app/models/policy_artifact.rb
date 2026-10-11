class PolicyArtifact < ApplicationRecord
  MAX_BYTES = 16 * 1024 * 1024
  IDENTITY_FORMAT = /\Asha256:[0-9a-f]{64}\z/
  class InvalidBytes < StandardError; end

  has_many :catalog_policy_artifacts, dependent: :restrict_with_exception
  attr_readonly :policy_identity, :artifact, :artifact_size, :source_host_id
  attr_accessor :defer_analysis

  validates :policy_identity, format: { with: IDENTITY_FORMAT }
  validates :artifact_size, numericality: { greater_than: 0, less_than_or_equal_to: MAX_BYTES }

  after_create_commit :enqueue_permissive_domain_analysis, unless: :defer_analysis

  def self.validate_bytes!(identity, bytes)
    raise InvalidBytes, "invalid policy identity" unless identity.to_s.match?(IDENTITY_FORMAT)
    raise InvalidBytes, "policy artifact size is invalid" unless bytes.is_a?(String) && bytes.bytesize.between?(1, MAX_BYTES)
    raise InvalidBytes, "policy artifact digest mismatch" unless "sha256:#{Digest::SHA256.hexdigest(bytes)}" == identity
  end

  def self.store!(policy_identity:, bytes:, source_host_id: nil, defer_analysis: false)
    validate_bytes!(policy_identity, bytes)
    create_or_find_by!(policy_identity: policy_identity) do |record|
      record.artifact = bytes
      record.artifact_size = bytes.bytesize
      record.source_host_id = source_host_id
      record.defer_analysis = defer_analysis
    end.tap(&:verify_bytes!)
  end

  def verify_bytes!
    self.class.validate_bytes!(policy_identity, artifact)
    raise InvalidBytes, "stored policy artifact size mismatch" unless artifact_size == artifact.bytesize

    self
  end

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
