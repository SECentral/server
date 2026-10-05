class OperatorApiController < ActionController::Base
  include OperatorAuthentication

  protect_from_forgery with: :exception

  private

  def operator_api_request?
    true
  end
end
