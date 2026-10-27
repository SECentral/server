require "rails_helper"

RSpec.describe "Captured fleet evidence" do
  captures = JSON.parse(File.read(Rails.root.join("spec/fixtures/contracts/real-fleet.json"))).fetch("cases")

  captures.each do |capture|
    it "preserves independent decision and syscall semantics for #{capture.fetch('name')}" do
      records = capture.fetch("records").map { |r| Struct.new(:type_name, :payload).new(r.fetch("type_name"), r.fetch("payload")) }
      decisions = AvcNormalizer.call(records)
      expected = capture.fetch("expected")
      expect(decisions.map { |d| d[:permissions] }).to eq(expected.fetch("permissions"))
      decisions.each do |decision|
        expect(decision).to include(status: "ok", source_type: "httpd_t", target_type: "user_home_t", target_class: "file")
        details = decision.deep_stringify_keys
        expect(NormalizedDenial.enforcement(details)).to eq(expected.fetch("enforcement"))
        expect(NormalizedDenial.syscall_outcome(details)).to eq(expected.fetch("syscall_outcome"))
      end
    end
  end

  it "retains host/boot provenance, groups cross-distribution decisions, and deduplicates replay" do
    ApplicationRecord.transaction do
      organization = Organization.create!(name: "Captured fleet")
      captures.each_with_index do |capture, index|
        timestamp = Time.at(1700000000 + index, 123000).utc.iso8601(6)
        expected = capture.fetch("expected")
        payload = {
          "schema_version" => 4, "agent" => { "version" => "0.0.5" },
          "host_id" => capture.fetch("host_id"), "boot_id" => capture.fetch("boot_id"),
          "events" => [{ "category" => "avc", "audit_event" => { "timestamp" => timestamp, "sequence" => expected.fetch("sequence") },
            "agent_received_at" => timestamp, "completion_reason" => expected.fetch("completion_reason"),
            "records" => capture.fetch("records").each_with_index.map do |record, position|
              { "position" => position, "type" => record.fetch("type_name").downcase, "type_name" => record.fetch("type_name"),
                "timestamp" => timestamp, "sequence" => expected.fetch("sequence"), "payload" => Base64.strict_encode64(record.fetch("payload")) }
            end }]
        }
        2.times { IngestEvents.new(organization: organization, payload: payload).call }
        raw = organization.raw_events.find_by!(audit_sequence: expected.fetch("sequence"))
        expect(raw.boot_id).to eq(capture.fetch("boot_id"))
        expect(raw.host.external_id).to eq(capture.fetch("host_id"))
        expect(raw.raw_audit_records.map(&:payload)).to eq(capture.fetch("records").map { |r| r.fetch("payload") })
        2.times { ProcessRawEvent.call(raw) }
        expect(raw.occurrences.count).to eq(expected.fetch("permissions").size)
      end
      expect(organization.hosts.count).to eq(2)
      expect(organization.raw_events.count).to eq(3)
      expect(organization.issues.count).to eq(1)
      summary = ObservationSummary.call(Occurrence.where(organization: organization))
      expect(summary).to include(occurrences: 4, audit_events: 3,
        modes: { "enforcing" => 2, "permissive" => 2 },
        syscall_outcomes: { "failed" => 1, "succeeded" => 1, "unknown" => 1 })
      raise ActiveRecord::Rollback
    end
  end
end
