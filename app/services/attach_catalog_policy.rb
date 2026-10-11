# Local administrative authority only; never called by browser/agent ingestion.
class AttachCatalogPolicy
  def self.call(revision:, bytes:, acquisition_basis:, attached_by: nil)
    PolicyArtifact.validate_bytes!(revision.loaded_policy_digest, bytes)
    revision.with_lock do
      artifact = PolicyArtifact.store!(policy_identity: revision.loaded_policy_digest, bytes: bytes, defer_analysis: true)
      existing = revision.reload.catalog_policy_artifact
      raise PolicyArtifact::InvalidBytes, "existing companion does not match exact policy artifact" if existing && existing.policy_artifact_id != artifact.id

      existing || revision.create_catalog_policy_artifact!(
        policy_artifact: artifact,
        source_kind: "administrative_cli", acquisition_basis: acquisition_basis, attached_by: attached_by
      )
    end
  end

  def self.read_file(path)
    raise PolicyArtifact::InvalidBytes, "policy path must be canonical without traversal or symlinks" if path.to_s.split("/").include?("..") || File.realpath(path) != File.expand_path(path)

    File.open(path, File::RDONLY | File::NOFOLLOW | File::NONBLOCK) do |file|
      raise PolicyArtifact::InvalidBytes, "policy input must be a regular file" unless file.stat.file?

      bytes = file.read(PolicyArtifact::MAX_BYTES + 1).to_s
      raise PolicyArtifact::InvalidBytes, "policy artifact size is invalid" unless bytes.bytesize.between?(1, PolicyArtifact::MAX_BYTES)

      bytes
    end
  end
end
