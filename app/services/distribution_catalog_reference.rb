class DistributionCatalogReference
  def self.for_snapshot(snapshot)
    selection = DistributionCatalogRevision.reference_for_snapshot(snapshot)
    from_revision(selection&.revision, applicability: selection&.applicability)
  end

  def self.for_policy_identity(policy_identity)
    return unless policy_identity.to_s.match?(/\Asha256:[0-9a-f]{64}\z/)

    from_revision(DistributionCatalogRevision.active.find_by(loaded_policy_digest: policy_identity))
  end

  def self.from_revision(revision, applicability: "exact")
    new(revision, applicability) if revision
  end

  attr_reader :revision, :applicability

  def initialize(revision, applicability)
    @revision = revision
    @applicability = applicability
  end

  def boolean_catalog
    return unless @revision.booleans_complete?

    attributes.merge("complete" => true, "booleans" => @revision.distribution_catalog_booleans.map { |boolean| { "name" => boolean.name, "default" => boolean.default_value, "description" => boolean.description } })
  end

  def port_catalog
    return unless @revision.ports_complete?

    attributes.merge("completeness" => @revision.port_catalog_completeness, "mappings" => @revision.port_catalog_mappings.map(&:stringify_keys))
  end

  private

  def attributes
    {
      "policy_identity" => @revision.loaded_policy_digest,
      "version" => @revision.content_digest,
      "provenance" => "Imported distribution catalog",
      "reference_source" => "distribution_catalog",
      "applicability" => @applicability,
      "content_digest" => @revision.content_digest,
      "loaded_policy_digest" => @revision.loaded_policy_digest,
      "distribution_catalog_revision_id" => @revision.id
    }
  end
end
