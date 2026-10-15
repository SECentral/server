class Api::V1::BaseController < OperatorApiController
  # Single product version, shared with the SPA build (frontend reads the same file).
  VERSION = File.read(Rails.root.join("VERSION")).strip
  CAPABILITIES = [
    "issue-intelligence",
    "issue-diagnosis",
    "issue-triage-signals",
    "diagnostic-hypotheses",
    "investigation-guidance",
    "host-configuration-comparison",
    "configuration-inventory",
    "distribution-catalogs"
  ].freeze

  # After the action so login responses carry a token bound to the
  # post-reset session.
  after_action :set_csrf_header

  rescue_from ActiveRecord::RecordNotFound do
    render json: { error: { code: "not_found", message: "Resource not found" } }, status: :not_found
  end

  rescue_from PageSize::Invalid do |error|
    render json: { error: { code: "invalid_value", message: error.message } }, status: :unprocessable_content
  end

  rescue_from ActiveRecord::SoleRecordExceeded do
    render json: { error: { code: "organization_unavailable", message: "Operator access requires exactly one organization" } }, status: :service_unavailable
  end

  rescue_from ActionController::InvalidAuthenticityToken do
    render json: { error: { code: "invalid_csrf_token", message: "Invalid or missing CSRF token" } }, status: :unprocessable_content
  end

  private

  def current_organization
    @current_organization ||= Organization.sole
  rescue ActiveRecord::RecordNotFound
    raise ActiveRecord::SoleRecordExceeded
  end

  def set_csrf_header
    response.headers["X-CSRF-Token"] = form_authenticity_token
  end
end
