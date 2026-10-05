class Api::V1::OverviewController < Api::V1::BaseController
  def show
    render json: OverviewQuery.new.call.to_h
  end
end
