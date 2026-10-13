class Api::V1::HostConfigurationsController < Api::V1::BaseController
  def show
    host = current_organization.hosts.includes(:agent_installations, current_state_observation: :host_snapshot).find(params[:id])
    render json: HostConfigurationQuery.call(
      host,
      view: params[:view].to_s,
      q: params[:q],
      page: params[:page],
      reference_revision_id: params[:reference_revision_id]
    )
  rescue CatalogReferenceSelection::InvalidRevision => error
    render json: { error: { code: "invalid_reference_revision", message: error.message } }, status: :unprocessable_content
  end
end
