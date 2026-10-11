class PolicyArtifactIngestion
  class InvalidArtifact < StandardError; end
  class HostIdentityMismatch < StandardError; end

  def self.call(host:, policy_identity:, bytes:)
    new(host, policy_identity, bytes).call
  end

  def initialize(host, policy_identity, bytes)
    @host = host
    @policy_identity = policy_identity
    @bytes = bytes
  end

  def call
    PolicyArtifact.validate_bytes!(@policy_identity, @bytes)
    # Refresh cached associations and serialize authorization with ingestion.
    @host.with_lock do
      raise HostIdentityMismatch unless @host.current_policy_identity == @policy_identity

      artifact = PolicyArtifact.store!(policy_identity: @policy_identity, bytes: @bytes, source_host_id: @host.external_id)

      PolicyFact.where(policy_identity: @policy_identity, status: "pending").find_each(&:enqueue_if_ready)
      artifact
    end
  rescue PolicyArtifact::InvalidBytes => error
    raise InvalidArtifact, error.message
  end
end
