class ExpectedContextObservationsController < ApplicationController
  include AgentAuthentication

  rescue_from JSON::ParserError, with: :malformed_json
  rescue_from PersistExpectedContextObservation::InvalidRequest, with: :invalid_request
  rescue_from PersistExpectedContextObservation::EvidenceConflict, with: :evidence_conflict
  rescue_from ActiveRecord::RecordNotFound, with: :event_not_found
  rescue_from ActiveRecord::RecordInvalid, with: :invalid_record

  before_action :authenticate_agent!, :resolve_ingestion_organization!

  def create
    PersistExpectedContextObservation.call(organization: @ingestion_organization, payload: JSON.parse(request.raw_post))
    head :accepted
  end

  private

  def malformed_json
    render json: { error: { code: "invalid_request", message: "Malformed JSON" } }, status: :bad_request
  end

  def invalid_request(error)
    render json: { error: { code: "invalid_request", message: "Request validation failed", details: error.details } }, status: :unprocessable_content
  end

  def evidence_conflict(error)
    render json: { error: { code: "evidence_conflict", message: error.message } }, status: :conflict
  end

  def event_not_found
    render json: { error: { code: "not_found", message: "Source audit event not found" } }, status: :not_found
  end

  def invalid_record(error)
    render json: { error: { code: "invalid_request", message: error.message } }, status: :unprocessable_content
  end
end
