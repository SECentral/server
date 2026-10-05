class Api::V1::CatalogsController < Api::V1::BaseController
  def index
    render json: { catalogs: catalog_list }
  end

  def show
    revision = DistributionCatalogRevision
      .includes(:distribution_catalog_booleans, :distribution_catalog_ports, :distribution_catalog_imports)
      .find(params[:id])
    render json: { catalog: catalog_payload(revision) }
  end

  private

  def catalog_list
    DistributionCatalogRevision
      .includes(:distribution_catalog_booleans, :distribution_catalog_ports)
      .order(created_at: :desc, id: :asc)
      .map { |revision| identity_payload(revision) }
  end

  def catalog_payload(revision)
    identity_payload(revision).merge(
      policy_packages: revision.policy_packages,
      imports: revision.distribution_catalog_imports.map do |import|
        { id: import.id, source_path: import.source_path, acquisition_metadata: import.acquisition_metadata, imported_at: import.created_at }
      end,
      booleans: revision.distribution_catalog_booleans.map do |entry|
        { name: entry.name, default_value: entry.default_value, description: entry.description }
      end,
      port_mappings: revision.port_catalog_mappings
    )
  end

  def identity_payload(revision)
    {
      id: revision.id,
      display_name: revision.display_name,
      distribution: revision.distribution,
      major_version: revision.major_version,
      architecture: revision.architecture,
      policy_type: revision.policy_type,
      kernel_policy_version: revision.kernel_policy_version,
      schema_version: revision.schema_version,
      collector_semantics_version: revision.collector_semantics_version,
      content_digest: revision.content_digest,
      loaded_policy_digest: revision.loaded_policy_digest,
      booleans_complete: revision.booleans_complete?,
      ports_complete: revision.ports_complete?,
      booleans_count: revision.distribution_catalog_booleans.size,
      port_mappings_count: revision.distribution_catalog_ports.size,
      created_at: revision.created_at
    }
  end
end
