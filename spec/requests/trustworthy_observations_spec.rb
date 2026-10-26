require "rails_helper"

RSpec.describe "Trustworthy observations", type: :request do
  include ActiveSupport::Testing::TimeHelpers

  around do |example|
    travel_to(Time.utc(2026, 10, 25, 12)) do
      ActiveRecord::Base.transaction do
        example.run
        raise ActiveRecord::Rollback
      end
    end
  end

  before do
    @organization = Organization.create!(name: "Trustworthy")
    @host = @organization.hosts.create!(external_id: "fixture", hostname: "fixture")
    @agent = @organization.agent_installations.create!(name: "fixture", bound_host: @host, last_seen_at: Time.current)
    sign_in_operator
  end

  def event(sequence, permissive:, success:, extra_avc: false)
    raw = @host.raw_events.create!(organization: @organization, agent_installation: @agent, audit_timestamp: Time.current,
      audit_sequence: sequence, boot_id: "boot", schema_version: 4, category: "avc", completion_reason: "timeout",
      evidence_digest: sequence.to_s, agent_received_at: Time.current, server_received_at: Time.current)
    avc = "type=AVC denied { read } scontext=u:r:httpd_t:s0 tcontext=u:object_r:var_t:s0 tclass=file"
    avc += " permissive=#{permissive}" unless permissive.nil?
    records = [avc]
    records.concat([avc.sub("{ read }", "{ open }"), avc.sub("tclass=file", "tclass=dir")]) if extra_avc
    records << "type=SYSCALL arch=c000003e syscall=2 success=#{success} exit=#{success == 'yes' ? '3' : '-13'}" if success
    records.each_with_index do |payload, index|
      raw.raw_audit_records.create!(position: index, record_type: payload.start_with?("type=AVC") ? 1400 : 1300,
        type_name: payload.start_with?("type=AVC") ? "AVC" : "SYSCALL", audit_timestamp: raw.audit_timestamp, sequence: sequence, payload: payload)
    end
    ProcessRawEvent.call(raw)
    raw
  end

  it "deduplicates syscall outcomes across decisions and issues, retaining mixed and unknown facts" do
    event(1, permissive: 0, success: "no", extra_avc: true)
    event(2, permissive: 1, success: "yes")
    event(3, permissive: nil, success: nil)
    denial = @host.occurrences.order(:id).first.normalized_denial
    denial.update!(details: denial.details.merge("retained_supplement" => "x" * 16_384))
    issue = Issue.find_by!(target_class: "file")
    summary = ObservationSummary.call(issue.occurrences)
    full_rows = issue.occurrences.joins(:normalized_denial).pluck(:raw_event_id, "normalized_denials.details")
    full_summary = ObservationSummary.from_rows(full_rows)
    expect(summary.except(:decision_outcomes)).to eq(full_summary.except(:decision_outcomes))
    expect(summary[:decision_outcomes]).to match_array(full_summary[:decision_outcomes])
    expect(denial.reload.details.fetch("retained_supplement").bytesize).to eq(16_384)
    expect(summary).to include(occurrences: 4, audit_events: 3, modes: { "enforcing" => 2, "permissive" => 1, "unknown" => 1 },
      syscall_outcomes: { "failed" => 1, "succeeded" => 1, "unknown" => 1 })
    fleet = ObservationSummary.call(Occurrence.all)
    expect(fleet).to include(occurrences: 5, audit_events: 3, syscall_outcomes: summary[:syscall_outcomes])
    expect(summary[:decision_outcomes]).to include(enforcement_mode: "enforcing", syscall_outcome: "failed", occurrences: 2)
    get "/api/v1/issues/#{issue.id}"
    body = JSON.parse(response.body)
    expect(body.dig("issue", "observations", "syscall_outcomes")).to eq("failed" => 1, "succeeded" => 1, "unknown" => 1)
    expect(body["supported_occurrence_count"]).to eq(0)
    expect(body.dig("policy_analysis", "occurrence_counts")).to include("unavailable" => 4)
    expect(body["operator_guidance"]).to be_present
    get "/api/v1/hosts/#{@host.id}"
    counts = JSON.parse(response.body).dig("host", "counts")
    expected = JSON.parse(ObservationSummary.call(Occurrence.where(host: @host)).to_json)
    expect(counts["observations"].except("decision_outcomes")).to eq(expected.except("decision_outcomes"))
    expect(counts["observations"]["decision_outcomes"]).to match_array(expected["decision_outcomes"])
    get "/api/v1/overview"
    expect(JSON.parse(response.body).dig("metrics", "observations_24h", "audit_events")).to eq(3)
  end

  it "keeps contradictory evidence unknown even across duplicated decision evidence" do
    expect(ObservationSummary.from_rows([[1, { "syscall_evidence" => [{ "success" => "no" }] }],
      [1, { "syscall_evidence" => [{ "success" => "yes" }] }]])).to include(audit_events: 1,
        syscall_outcomes: { "failed" => 0, "succeeded" => 0, "unknown" => 1 })
  end

  it "reports stopped agents and unknown capture coverage independently of zero observations" do
    get "/api/v1/hosts/#{@host.id}"
    host = JSON.parse(response.body).fetch("host")
    expect(host.dig("agent", "reporting_state")).to eq("reporting")
    expect(host.dig("counts", "observations", "audit_events")).to eq(0)
    expect(host.dig("observation", "status")).to eq("none")
    expect(host.dig("telemetry", "audit_capture")).to eq("unknown")
    expect(host.dig("reporting_observations", "status")).to eq("unknown")
    travel 2.days
    get "/api/v1/hosts/#{@host.id}"
    expect(JSON.parse(response.body).dig("host", "agent", "reporting_state")).to eq("offline")
  end
end
