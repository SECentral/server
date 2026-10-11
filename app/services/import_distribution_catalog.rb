class ImportDistributionCatalog
  Result = Data.define(:revision, :catalog_import, :created)
  Preview = Data.define(:artifact, :outcome, :revision, :display_name)

  class Conflict < StandardError; end
  class InvalidName < StandardError; end

  def self.call(artifact:, source_path: nil, display_name: nil, imported_by: nil, source_kind: "unspecified")
    new(artifact, source_path, display_name, imported_by, source_kind).call
  end

  def self.preview(artifact:, display_name: nil)
    new(artifact, nil, display_name, nil, "unspecified").preview
  end

  def initialize(artifact, source_path, display_name, imported_by, source_kind)
    @artifact = artifact
    @source_path = source_path
    @display_name = display_name
    @imported_by = imported_by
    @source_kind = source_kind
  end

  def preview
    @artifact.validate!
    name = initial_name
    revision = DistributionCatalogRevision.find_by(content_digest: @artifact.content_digest)
    return Preview.new(@artifact, "reuse_existing_revision", revision, revision.display_name) if revision

    conflict = DistributionCatalogRevision.find_by(loaded_policy_digest: @artifact.catalog.dig("policy", "loaded_policy_digest"))
    Preview.new(@artifact, conflict ? "conflict" : "create_new_revision", conflict, name)
  end

  def call
    @artifact.validate!
    name = initial_name
    retried = false
    begin
      ActiveRecord::Base.transaction do
        revision = DistributionCatalogRevision.find_by(content_digest: @artifact.content_digest)
        created = revision.nil?
        if created
          conflict = DistributionCatalogRevision.find_by(loaded_policy_digest: @artifact.catalog.dig("policy", "loaded_policy_digest"))
          raise Conflict, "conflicting catalog for loaded policy digest" if conflict

          revision = DistributionCatalogRevision.create!(revision_attributes.merge(initial_display_name: name))
          create_children(revision)
        end
        comparison_report = CatalogImportComparison.call(revision, created: created)
        catalog_import = revision.distribution_catalog_imports.create!(artifact: @artifact.artifact, acquisition_metadata: @artifact.metadata, source_path: @source_path, imported_by: @imported_by, source_kind: @source_kind, comparison_report: comparison_report)
        Result.new(revision, catalog_import, created)
      end
    rescue ActiveRecord::RecordNotUnique
      # A competing transaction won creation. Retry after rollback using the same
      # content/policy checks, rather than exposing a uniqueness error to CLI/UI.
      raise if retried || !DistributionCatalogRevision.where(content_digest: @artifact.content_digest).or(DistributionCatalogRevision.where(loaded_policy_digest: @artifact.catalog.dig("policy", "loaded_policy_digest"))).exists?

      retried = true
      retry
    end
  end

  private

  def initial_name
    revision = DistributionCatalogRevision.new(revision_attributes)
    raise InvalidName, "Display name must be a valid string" unless @display_name.nil? || (@display_name.is_a?(String) && @display_name.valid_encoding?)

    name = @display_name.nil? ? revision.default_display_name : @display_name.strip
    management = CatalogManagement.new(distribution_catalog_revision: revision, display_name: name, lifecycle: "active")
    raise InvalidName, management.errors.full_messages.join(", ") unless management.valid?

    name
  end

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
