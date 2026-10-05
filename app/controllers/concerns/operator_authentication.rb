module OperatorAuthentication
  extend ActiveSupport::Concern

  included do
    before_action :authenticate_operator!
  end

  private

  def authenticate_operator!
    return if session[:operator_username].present? && session[:operator_username] == operator_username

    render json: { error: { code: "unauthorized", message: "Authentication required" } }, status: :unauthorized
  end

  def operator_username
    ENV["ADMIN_USERNAME"].presence
  end

  def operator_password_digest
    ENV["ADMIN_PASSWORD_DIGEST"].presence
  end

  def operator_credentials_configured?
    operator_username.present? && operator_password_digest.present?
  end

  def valid_operator_credentials?(username, password)
    return false unless operator_credentials_configured?
    return false unless ActiveSupport::SecurityUtils.secure_compare(username.to_s, operator_username)

    BCrypt::Password.new(operator_password_digest) == password.to_s
  rescue BCrypt::Errors::InvalidHash
    false
  end
end
