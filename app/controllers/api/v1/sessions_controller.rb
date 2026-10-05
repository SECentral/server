class Api::V1::SessionsController < Api::V1::BaseController
  skip_before_action :authenticate_operator!, only: :create
  skip_before_action :verify_authenticity_token, only: :create

  def show
    render json: { operator: { username: operator_username } }
  end

  def create
    if valid_operator_credentials?(params[:username], params[:password])
      reset_session
      session[:operator_username] = operator_username
      render json: { operator: { username: operator_username } }, status: :created
    else
      render json: { error: { code: "unauthorized", message: "Invalid credentials" } }, status: :unauthorized
    end
  end

  def destroy
    reset_session
    head :no_content
  end
end
