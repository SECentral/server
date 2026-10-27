require "rails_helper"

RSpec.describe "Buffered audit event delivery" do
  include ActiveSupport::Testing::TimeHelpers

  it "retains event and receipt times and deduplicates retries with different batching" do
    capture = JSON.parse(File.read(Rails.root.join("spec/fixtures/contracts/buffered-events.json")))
    payload = capture.fetch("request")
    ApplicationRecord.transaction do
      organization = Organization.create!(name: "Buffered events")
      capture.fetch("deliveries").each do |delivery|
        events = payload.fetch("events").select { |event| delivery.fetch("sequences").include?(event.dig("audit_event", "sequence")) }
        travel_to(Time.iso8601(delivery.fetch("received_at")), with_usec: true) do
          IngestEvents.new(organization: organization, payload: payload.merge("events" => events)).call
        end
      end
      raw = organization.raw_events.order(:audit_sequence).to_a
      expect(raw.map(&:audit_sequence)).to eq([2001, 2002, 2003])
      raw.zip(payload.fetch("events")).each do |event, input|
        expect(event.audit_timestamp).to eq(Time.iso8601(input.dig("audit_event", "timestamp")))
        expect(event.server_received_at).to be > event.audit_timestamp
        expect(event.raw_audit_records.map(&:payload)).to eq(input.fetch("records").map { |r| Base64.strict_decode64(r.fetch("payload")) })
        ProcessRawEvent.call(event)
      end
      expect(raw.map(&:server_received_at)).to eq(capture.fetch("deliveries").flat_map { |d| [Time.iso8601(d.fetch("received_at"))] * d.fetch("sequences").size })
      original = organization.raw_events.order(:id).map(&:attributes)
      travel_to(Time.iso8601(capture.fetch("deliveries").last.fetch("received_at")) + 1.minute, with_usec: true) do
        2.times { IngestEvents.new(organization: organization, payload: payload).call }
      end
      expect(organization.raw_events.order(:id).map(&:attributes)).to eq(original)
      expect(organization.issues.count).to eq(1)
      expect(ObservationSummary.call(Occurrence.where(organization: organization))).to include(
        occurrences: 3, audit_events: 3, syscall_outcomes: { "failed" => 3, "succeeded" => 0, "unknown" => 0 })
      raise ActiveRecord::Rollback
    end
  end
end
