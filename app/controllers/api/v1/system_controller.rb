class Api::V1::SystemController < Api::V1::BaseController
  def show
    render json: {
      api_version: "v1",
      server_version: Api::V1::BaseController::VERSION,
      capabilities: Api::V1::BaseController::CAPABILITIES
    }
  end
end
