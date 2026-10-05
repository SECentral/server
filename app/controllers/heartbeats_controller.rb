class HeartbeatsController < ApplicationController
  include AgentAuthentication

  rescue_from JSON::ParserError, with: :malformed_json
  rescue_from Heartbeat::InvalidRequest, with: :invalid_request
  rescue_from ActiveRecord::RecordInvalid, with: :invalid_record

  before_action :authenticate_agent!, :resolve_ingestion_organization!

  def create
    result = Heartbeat.call(organization: @ingestion_organization, payload: JSON.parse(request.raw_post))
    render json: result, status: :accepted
  end

  private

  def malformed_json
    render json: { error: { code: "invalid_request", message: "Malformed JSON" } }, status: :bad_request
  end

  def invalid_request(error)
    render json: { error: { code: "invalid_request", message: "Request validation failed", details: error.details } }, status: :unprocessable_content
  end

  def invalid_record(error)
    render json: { error: { code: "invalid_request", message: error.message } }, status: :unprocessable_content
  end
end
