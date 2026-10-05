class Api::V1::HostSelinuxActivitiesController < Api::V1::BaseController
  def index
    activity = HostSelinuxActivity.new(Host.find(params[:id]))
    render json: activity.page(before: params[:before], occurrence_id: params[:occurrence_id], event_id: params[:event_id], page: params[:page])
  rescue ArgumentError
    render json: { error: { code: "invalid_value", message: "Invalid activity cursor or page" } }, status: :unprocessable_content
  end

  def show
    render json: { item: HostSelinuxActivity.new(Host.find(params[:id])).detail(params[:event_id]) }
  end
end
