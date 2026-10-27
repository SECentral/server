require "rails_helper"

RSpec.describe "Occurrence evidence timing", type: :request do
  include ActiveSupport::Testing::TimeHelpers

  around do |example|
    ApplicationRecord.transaction do
      example.run
      raise ActiveRecord::Rollback
    end
  end

  before do
    @capture = JSON.parse(File.read(Rails.root.join("spec/fixtures/contracts/buffered-events.json")))
    @payload = @capture.fetch("request")
    @organization = Organization.create!(name: "Occurrence timing")
    @capture.fetch("deliveries").each do |delivery|
      events = @payload.fetch("events").select { |event| delivery.fetch("sequences").include?(event.dig("audit_event", "sequence")) }
      travel_to(Time.iso8601(delivery.fetch("received_at")), with_usec: true) do
        IngestEvents.new(organization: @organization, payload: @payload.merge("events" => events)).call
      end
    end
    @organization.raw_events.each { |raw| ProcessRawEvent.call(raw) }
    sign_in_operator
  end

  it "exposes original microsecond times on both detail routes after duplicate ingestion and reprocessing" do
    original = @organization.raw_events.order(:id).map do |raw|
      [raw.audit_timestamp, raw.server_received_at, raw.raw_audit_records.map(&:payload)]
    end
    travel_to(Time.iso8601(@capture.fetch("deliveries").last.fetch("received_at")) + 1.hour, with_usec: true) do
      IngestEvents.new(organization: @organization, payload: @payload).call
      @organization.raw_events.each do |raw|
        raw.touch
        ProcessRawEvent.call(raw)
      end
    end
    expect(@organization.raw_events.order(:id).map { |raw| [raw.audit_timestamp, raw.server_received_at, raw.raw_audit_records.map(&:payload)] }).to eq(original)

    @organization.raw_events.order(:audit_sequence).each_with_index do |raw, index|
      occurrence = raw.occurrences.sole
      input = @payload.fetch("events")[index]
      delivery = @capture.fetch("deliveries").find { |item| item.fetch("sequences").include?(raw.audit_sequence) }
      ["/api/v1/hosts/#{raw.host_id}/occurrences/#{occurrence.id}", "/api/v1/issues/#{occurrence.issue_id}/occurrences/#{occurrence.id}"].each do |url|
        get url
        expect(response).to have_http_status(:ok)
        body = JSON.parse(response.body)
        expect(body.dig("raw_event", "audit_timestamp")).to eq(Time.iso8601(input.dig("audit_event", "timestamp")).iso8601(6))
        expect(body.dig("raw_event", "collection", "server_received_at")).to eq(delivery.fetch("received_at"))
        expect(body.dig("raw_event", "audit_records").map { |r| r.fetch("payload") }).to eq(original[index].last)
        expect(occurrence.occurred_at).to eq(raw.audit_timestamp)
      end
    end
    expect(Occurrence.where(organization: @organization).count).to eq(3)
    expect(@organization.issues.count).to eq(1)
  end

  it "projects an unavailable receipt explicitly without a creation-time fallback" do
    occurrence = Occurrence.where(organization: @organization).first!
    occurrence.raw_event.server_received_at = nil
    body = OccurrenceDetailSerializer.call(occurrence)
    expect(body.dig(:raw_event, :collection)).to have_key(:server_received_at)
    expect(body.dig(:raw_event, :collection, :server_received_at)).to be_nil
    expect(body.dig(:raw_event, :audit_timestamp)).to eq(occurrence.raw_event.audit_timestamp.iso8601(6))
  end
end
