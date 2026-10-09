class Api::V1::CatalogsController < Api::V1::BaseController
  wrap_parameters false

  def index
    render json: { catalogs: catalog_list }
  end

  def show
    revision = DistributionCatalogRevision
      .includes(:catalog_management, :distribution_catalog_booleans, :distribution_catalog_ports, :distribution_catalog_imports)
      .find(params[:id])
    render json: { catalog: catalog_payload(revision) }
  end

  def rename
    manage_catalog(allowed: ["display_name"]) do |management|
      raise ArgumentError, "display_name must be a string" unless params[:display_name].is_a?(String)

      management.change!(display_name: params[:display_name], changed_by: operator_username)
    end
  end

  def archive
    manage_catalog { |management| management.change!(lifecycle: "archived", changed_by: operator_username) }
  end

  def unarchive
    manage_catalog { |management| management.change!(lifecycle: "active", changed_by: operator_username) }
  end

  private

  def manage_catalog(allowed: [])
    input_keys = request.request_parameters.keys | request.query_parameters.keys
    raise ArgumentError, "Only #{allowed.join(', ').presence || 'an empty body'} is accepted" if (input_keys - allowed).any?

    revision = DistributionCatalogRevision.includes(:catalog_management, :distribution_catalog_booleans, :distribution_catalog_ports, :distribution_catalog_imports).find(params[:id])
    yield revision.catalog_management
    render json: { catalog: catalog_payload(revision) }
  rescue ArgumentError, ActiveRecord::RecordInvalid => error
    render json: { error: { code: "invalid_catalog_management", message: error.message } }, status: :unprocessable_content
  end

  def catalog_list
    DistributionCatalogRevision
      .includes(:catalog_management, :distribution_catalog_booleans, :distribution_catalog_ports)
      .order(created_at: :desc, id: :asc)
      .map { |revision| identity_payload(revision) }
  end

  def catalog_payload(revision)
    identity_payload(revision).merge(
      policy_packages: revision.policy_packages,
      imports: revision.distribution_catalog_imports.map do |import|
        { id: import.id, source_path: import.source_path, source_kind: import.source_kind, imported_by: import.imported_by, acquisition_metadata: import.acquisition_metadata, imported_at: import.created_at }
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
      lifecycle: revision.catalog_management.lifecycle,
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
