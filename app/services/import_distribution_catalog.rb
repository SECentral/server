class ImportDistributionCatalog
  Result = Data.define(:revision, :catalog_import, :created)

  class Conflict < StandardError; end

  def self.call(artifact:, source_path: nil)
    new(artifact, source_path).call
  end

  def initialize(artifact, source_path)
    @artifact = artifact
    @source_path = source_path
  end

  def call
    @artifact.validate!
    ActiveRecord::Base.transaction do
      revision = DistributionCatalogRevision.find_by(content_digest: @artifact.content_digest)
      created = revision.nil?
      if created
        conflict = DistributionCatalogRevision.find_by(loaded_policy_digest: @artifact.catalog.dig("policy", "loaded_policy_digest"))
        raise Conflict, "conflicting catalog for loaded policy digest" if conflict

        revision = DistributionCatalogRevision.create!(revision_attributes)
        create_children(revision)
      end
      catalog_import = revision.distribution_catalog_imports.create!(artifact: @artifact.artifact, acquisition_metadata: @artifact.metadata, source_path: @source_path)
      Result.new(revision, catalog_import, created)
    end
  end

  private

  def revision_attributes
    policy = @artifact.catalog.fetch("policy")
    platform = @artifact.catalog.fetch("platform")
    families = @artifact.catalog.fetch("families")
    {
      schema_version: @artifact.catalog.fetch("schema_version", DistributionCatalogArtifact::SCHEMA_VERSION),
      content_digest: @artifact.content_digest,
      collector_semantics_version: @artifact.catalog.fetch("collector_semantics_version"),
      loaded_policy_digest: policy.fetch("loaded_policy_digest"),
      policy_type: policy.fetch("type"),
      kernel_policy_version: policy.fetch("kernel_policy_version"),
      distribution: platform.fetch("distribution"),
      major_version: platform.fetch("major_version"),
      architecture: platform.fetch("architecture"),
      policy_packages: policy.fetch("packages"),
      booleans_complete: families.dig("booleans", "complete"),
      ports_complete: families.dig("ports", "complete")
    }
  end

  def create_children(revision)
    @artifact.catalog.dig("families", "booleans", "entries").each do |entry|
      revision.distribution_catalog_booleans.create!(name: entry.fetch("name"), default_value: entry.fetch("default"), description: entry.fetch("description"))
    end
    @artifact.catalog.dig("families", "ports", "mappings").each do |mapping|
      revision.distribution_catalog_ports.create!(protocol: mapping.fetch("protocol"), start_port: mapping.fetch("start"), end_port: mapping.fetch("end"), selinux_type: mapping.fetch("type"))
    end
  end
end
