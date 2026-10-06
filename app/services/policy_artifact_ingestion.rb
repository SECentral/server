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
    raise InvalidArtifact, "invalid policy identity" unless @policy_identity.to_s.match?(PolicyArtifact::IDENTITY_FORMAT)
    raise InvalidArtifact, "policy artifact size is invalid" unless @bytes.is_a?(String) && @bytes.bytesize.between?(1, PolicyArtifact::MAX_BYTES)
    raise InvalidArtifact, "policy artifact digest mismatch" unless identity_for(@bytes) == @policy_identity
    # Refresh cached associations and serialize authorization with ingestion.
    @host.with_lock do
      raise HostIdentityMismatch unless @host.current_policy_identity == @policy_identity

      artifact = PolicyArtifact.create_or_find_by!(policy_identity: @policy_identity) do |record|
        record.artifact = @bytes
        record.artifact_size = @bytes.bytesize
        record.source_host_id = @host.external_id
      end
      raise InvalidArtifact, "stored policy artifact is corrupt" unless identity_for(artifact.artifact) == @policy_identity

      PolicyFact.where(policy_identity: @policy_identity, status: "pending").find_each(&:enqueue_if_ready)
      artifact
    end
  end

  private

  def identity_for(bytes)
    "sha256:#{Digest::SHA256.hexdigest(bytes)}"
  end
end
