class Api::V1::HostConfigurationsController < Api::V1::BaseController
  def show
    host = Host.includes(:agent_installations, current_state_observation: :host_snapshot).find(params[:id])
    render json: HostConfigurationQuery.call(
      host,
      view: params[:view].to_s,
      q: params[:q],
      page: params[:page]
    )
  end
end
