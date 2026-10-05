class EventsController < ApplicationController
  include AgentAuthentication
  rescue_from JSON::ParserError, with: :malformed_json
  rescue_from ActionDispatch::Http::Parameters::ParseError, with: :malformed_json
  rescue_from IngestEvents::InvalidRequest, with: :invalid_request
  rescue_from ActiveRecord::RecordInvalid, with: :invalid_record

  before_action :authenticate_agent!, :resolve_ingestion_organization!

  def create
    raw_events = IngestEvents.new(organization: @ingestion_organization, payload: JSON.parse(request.raw_post)).call
    avc_events = raw_events.select(&:avc?)
    avc_events.each do |raw_event|
      ProcessRawEvent.call(raw_event)
    end
    begin
      RequestPolicyFactsJob.perform_later(raw_event_ids: avc_events.map(&:id)) if avc_events.any?
    rescue StandardError => error
      Rails.logger.warn("policy fact request enqueue failed: #{error.message}")
    end
    head :accepted
  end

  private

  def malformed_json
    render_error("invalid_request", "Malformed JSON", :bad_request)
  end

  def invalid_request(error)
    render json: { error: { code: "invalid_request", message: "Request validation failed", details: error.details } }, status: :unprocessable_entity
  end

  def invalid_record(error)
    render json: { error: { code: "invalid_request", message: error.message } }, status: :unprocessable_entity
  end

  def render_error(code, message, status)
    render json: { error: { code: code, message: message } }, status: status
  end
end
