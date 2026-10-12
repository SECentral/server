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
    version = PolicyPermissiveDomainAnalyzer::SEMANTICS_VERSION
    return if analysis["semantics_version"].is_a?(Integer) && analysis["semantics_version"] > version
    return if current_permissive_domain_analysis? && analysis["status"] != "pending"
    return if current_permissive_domain_analysis? && analysis["last_enqueued_at"] && Time.iso8601(analysis["last_enqueued_at"]) > PolicyFact::ENQUEUE_INTERVAL.ago

    enqueue = with_lock do
      analysis = permissive_domain_analysis
      next false if analysis["semantics_version"].is_a?(Integer) && analysis["semantics_version"] > version
      next false if current_permissive_domain_analysis? && analysis["status"] != "pending"
      next false if current_permissive_domain_analysis? && analysis["last_enqueued_at"] && Time.iso8601(analysis["last_enqueued_at"]) > PolicyFact::ENQUEUE_INTERVAL.ago

      update_column(:permissive_domain_analysis, { "status" => "pending", "policy_identity" => policy_identity,
        "semantics_version" => version, "last_enqueued_at" => Time.current.iso8601(6) })
      true
    end
    AnalyzePolicyPermissiveDomainsJob.perform_later(id, version) if enqueue
  rescue StandardError => error
    Rails.logger.warn("permissive-domain analysis enqueue failed artifact=#{id}: #{error.message}")
  end

  def current_permissive_domain_analysis?
    result = permissive_domain_analysis
    result["semantics_version"].is_a?(Integer) && result["semantics_version"] == PolicyPermissiveDomainAnalyzer::SEMANTICS_VERSION && result["policy_identity"] == policy_identity &&
      %w[pending observed unavailable error].include?(result["status"]) &&
      (result["status"] != "observed" || (PolicyPermissiveDomainAnalyzer.valid_domains?(result["domains"]) && result["domains"] == result["domains"].uniq.sort && PolicyPermissiveDomainAnalyzer.valid_evaluator_version?(result["evaluator_version"])))
  end

  def invalidate_permissive_domain_analysis!(reason)
    with_lock do
      previous_version = permissive_domain_analysis["semantics_version"]
      version = PolicyPermissiveDomainAnalyzer::SEMANTICS_VERSION
      version = [version, previous_version].max if previous_version.is_a?(Integer)
      update_column(:permissive_domain_analysis, { "status" => "unavailable", "policy_identity" => policy_identity,
        "semantics_version" => version,
        "error_message" => reason, "evaluated_at" => Time.current.iso8601(6) })
    end
  end
end
