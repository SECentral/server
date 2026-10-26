require "rails_helper"

RSpec.describe "Heartbeat reporting duration", type: :request do
  include ActiveSupport::Testing::TimeHelpers

  let(:start) { Time.utc(2026, 10, 13, 10) }
  let(:headers) { { "CONTENT_TYPE" => "application/json", "Authorization" => "Bearer test-ingestion-key" } }
  let(:organization) { Organization.create!(name: "Reporting duration") }

  before { cleanup; organization }
  after { cleanup }

  it "starts at zero without crediting a legacy coalesced span" do
    legacy = organization.hosts.create!(external_id: "reporting-host", last_seen_at: start)
    snapshot = legacy.host_snapshots.create!(details: { "boot_id" => "boot-1", "selinux" => { "enforcement" => "enforcing" } })
    installation = legacy.agent_installations.create!(organization: organization, name: legacy.external_id)
    legacy.host_snapshot_observations.create!(host_snapshot: snapshot, agent_installation: installation,
      first_observed_at: start - 30.days, last_observed_at: start, first_received_at: start - 30.days, last_received_at: start)
    expect(HostEnforcingReadiness.call(legacy, at: start)).to include(status: "unknown", reason: "reporting_not_tracked")
    send_heartbeat(start)
    expect(host.reload.reporting_started_at).to eq(start)
    expect(credit).to eq(0)
    expect(readiness).to include(status: "observed", band: nil, capture_continuity: "unknown")
  end

  it "credits elapsed time despite identical-state coalescing" do
    send_heartbeat(start)
    send_heartbeat(start + 5.minutes)
    expect([HostSnapshot.count, HostSnapshotObservation.count]).to eq([1, 1])
    expect(credit).to eq(300)
    expect(host.reload.reporting_received_at).to eq(start + 5.minutes)
  end

  it "caps by first receipt time, not a retry's coalesced receipt" do
    send_heartbeat(start)
    send_heartbeat(start, received_at: start + 4.minutes)
    expect(host.reload.current_state_observation.last_received_at).to eq(start + 4.minutes)
    expect(host.reporting_received_at).to eq(start)
    send_heartbeat(start + 5.minutes)
    expect(credit).to eq(300)
    send_heartbeat(start + 10.minutes, received_at: start + 6.minutes)
    expect(credit).to eq(360)
  end

  it "does not credit delayed samples delivered in a short burst as ten minutes" do
    send_heartbeat(start, received_at: start + 10.minutes)
    send_heartbeat(start + 5.minutes, received_at: start + 10.minutes + 1.second)
    send_heartbeat(start + 10.minutes, received_at: start + 10.minutes + 2.seconds)
    expect(credit).to eq(2)
  end

  it "ignores duplicate and out-of-order samples without advancing duration or freshness" do
    send_heartbeat(start)
    send_heartbeat(start + 5.minutes)
    original = host.reload.attributes.slice("reporting_observed_at", "reporting_received_at", "reporting_sample_status")
    send_heartbeat(start + 5.minutes, received_at: start + 8.minutes)
    send_heartbeat(start + 2.minutes, received_at: start + 9.minutes)
    expect(host.reload.attributes.slice(*original.keys)).to eq(original)
    expect(credit).to eq(300)
  end

  it "normalizes nanosecond retries to database precision" do
    source = start + Rational(123456789, 1_000_000_000)
    send_heartbeat(source, received_at: start + 1.second)
    send_heartbeat(source, received_at: start + 2.seconds)
    expect(credit).to eq(0)
    expect(host.reload.reporting_observed_at.nsec).to eq(123456000)
    expect(host.reporting_received_at).to eq(start + 1.second)
  end

  it "caps missed samples and pauses long gaps without deleting accumulated credit" do
    send_heartbeat(start)
    send_heartbeat(start + 5.minutes)
    send_heartbeat(start + 15.minutes)
    expect(credit).to eq(600)
    send_heartbeat(start + 2.days)
    expect(credit).to eq(600)
    send_heartbeat(start + 2.days + 5.minutes)
    expect(credit).to eq(900)
  end

  it "retains credit through a reboot and ignores replay from the earlier boot" do
    send_heartbeat(start)
    send_heartbeat(start + 5.minutes)
    send_heartbeat(start + 6.minutes, boot: "boot-2")
    expect(credit).to eq(300)
    send_heartbeat(start + 7.minutes, boot: "boot-1")
    expect(host.reload.reporting_boot_id).to eq("boot-2")
    expect(readiness).to include(status: "unknown", reason: "checkpoint_boot_mismatch")
    send_heartbeat(start + 11.minutes, boot: "boot-2")
    expect(credit).to eq(600)
    expect(readiness).to include(status: "observed")
  end

  it "excludes unknown/disabled samples and resumes without resetting earlier days" do
    send_heartbeat(start, mode: "permissive")
    send_heartbeat(start + 5.minutes)
    send_heartbeat(start + 10.minutes, mode: "unknown")
    expect(readiness).to include(status: "unknown", reason: "enforcement_unavailable")
    send_heartbeat(start + 15.minutes, mode: "disabled")
    send_heartbeat(start + 20.minutes)
    expect(credit).to eq(300)
    send_heartbeat(start + 25.minutes)
    expect(credit).to eq(600)
  end

  it "withholds skewed delivery and requires a fresh pair to recover" do
    send_heartbeat(start)
    send_heartbeat(start + 5.minutes, received_at: start + 30.minutes)
    expect(readiness).to include(status: "unknown", reason: "reporting_time_unknown")
    send_heartbeat(start + 31.minutes)
    expect(readiness).to include(status: "unknown", reason: "reporting_time_unknown")
    send_heartbeat(start + 36.minutes)
    expect(credit).to eq(300)
    expect(readiness).to include(status: "observed")
  end

  it "does not bypass an existing future checkpoint to manufacture recovery time" do
    send_heartbeat(start)
    send_heartbeat(start + 1.hour, received_at: start + 1.minute)
    send_heartbeat(start + 5.minutes)
    expect(credit).to eq(0)
    expect(readiness).to include(status: "unknown", reason: "reporting_time_unknown")
    expect(host.reload.current_state_observation.last_observed_at).to eq(start + 1.hour)
  end

  it "does not count withheld policy-transition checkpoint publication" do
    send_heartbeat(start)
    raw_event(start + 6.minutes, category: "selinux_administrative", transition: "policy_load")
    send_heartbeat(start + 5.minutes)
    expect(host.reload.reporting_observed_at).to eq(start)
    expect(credit).to eq(0)
  end

  it "splits credit at UTC midnight and preserves integer microseconds" do
    midnight = Time.utc(2026, 10, 14)
    send_heartbeat(midnight - 2.minutes)
    send_heartbeat(midnight + 3.minutes)
    expect(host.host_reporting_days.order(:observed_on).pluck(:credited_microseconds)).to eq([120_000_000, 180_000_000])
    send_heartbeat(midnight + 3.minutes + Rational(1, 1_000_000))
    expect(credit).to eq(300.000001)
  end

  it "rolls back cursor/day/checkpoint writes together, then retries once" do
    send_heartbeat(start)
    allow_any_instance_of(HostReportingDay).to receive(:save!).and_raise(ActiveRecord::RecordInvalid.new(HostReportingDay.new))
    send_heartbeat(start + 5.minutes, accepted: false)
    expect(host.reload.reporting_observed_at).to eq(start)
    expect(host.current_state_observation.last_observed_at).to eq(start)
    expect(credit).to eq(0)
    allow_any_instance_of(HostReportingDay).to receive(:save!).and_call_original
    send_heartbeat(start + 5.minutes, received_at: start + 6.minutes)
    send_heartbeat(start + 5.minutes, received_at: start + 7.minutes)
    expect(credit).to eq(300)
  end

  it "serializes concurrent duplicate delivery under the existing host lock" do
    send_heartbeat(start)
    travel_to(start + 5.minutes) do
      threads = 2.times.map do
        Thread.new do
          ActiveRecord::Base.connection_pool.with_connection do
            Heartbeat.call(organization: organization, payload: payload(start + 5.minutes))
          end
        end
      end
      threads.each(&:value)
    end
    expect(credit).to eq(300)
    expect(host.host_reporting_days.count).to eq(1)
  end

  it "returns Unknown when receipts/events are fresh but the source cursor is stale" do
    send_heartbeat(start)
    send_heartbeat(start + 5.minutes)
    send_heartbeat(start + 5.minutes, received_at: start + 20.minutes)
    expect(HostEnforcingReadiness.call(host.reload, at: start + 20.minutes)).to include(status: "unknown", reason: "reporting_stale", band: nil)
    expect(credit).to eq(300)
  end

  it "does not use event-only receipt as heartbeat credit or readiness freshness" do
    send_heartbeat(start)
    send_heartbeat(start + 5.minutes)
    at = start + 20.minutes
    travel_to(at) do
      record = { "position" => 0, "type" => 1400, "type_name" => "AVC", "timestamp" => at.iso8601,
        "sequence" => 100, "payload" => Base64.strict_encode64("audit(#{at.to_i}:100): avc: denied { read } for scontext=a:b:httpd_t:s0 tcontext=a:b:user_home_t:s0 tclass=file permissive=0") }
      IngestEvents.new(organization: organization, payload: { "schema_version" => 4, "host_id" => host.external_id,
        "boot_id" => "boot-1", "agent" => { "version" => "test" }, "events" => [{ "category" => "avc",
          "audit_event" => { "timestamp" => at.iso8601, "sequence" => 100 }, "agent_received_at" => at.iso8601,
          "completion_reason" => "eoe", "records" => [record] }] }).call
    end
    expect(host.reload.last_seen_at).to eq(at)
    expect(host.reporting_received_at).to eq(start + 5.minutes)
    expect(credit).to eq(300)
    expect(HostEnforcingReadiness.call(host, at: at)).to include(status: "unknown", reason: "reporting_stale")
  end

  it "returns Unknown when a known boundary masks current enforcement" do
    send_heartbeat(start)
    raw_event(start + 1.minute, category: "selinux_administrative", transition: "enforcement_change")
    expect(HostEnforcingReadiness.call(host.reload, at: start + 2.minutes)).to include(status: "unknown", reason: "enforcement_unavailable")
  end

  it "recalculates eligible days from original AVC time, including ungroupable evidence" do
    send_heartbeat(start)
    host.update!(reporting_started_at: (start - 3.days).beginning_of_day)
    3.times { |n| host.host_reporting_days.create!(observed_on: start.to_date - n - 1, credited_microseconds: 86_400_000_000) }
    expect(readiness[:credited_seconds]).to eq(3 * 86_400)
    denial = raw_event(start - 2.days)
    expect(denial.normalized_denials).to be_empty
    expect(readiness[:credited_seconds]).to eq(86_400)
    raw_event(start - 3.days)
    expect(readiness[:latest_avc_at]).to eq(start - 2.days)
    raw_event(start)
    expect(readiness[:credited_seconds]).to eq(0)
    expect(credit).to eq(3 * 86_400)
  end

  it "does not treat administrative activity as a denial or a future denial as benign" do
    send_heartbeat(start)
    host.host_reporting_days.find_by!(observed_on: start.to_date).update!(credited_microseconds: 300_000_000)
    raw_event(start, category: "selinux_administrative")
    expect(readiness[:credited_seconds]).to eq(300)
    raw_event(start + 1.hour)
    expect(readiness).to include(status: "unknown", reason: "denial_time_unavailable", band: nil)
  end

  [0, 6, 12, 18, 24, 30, 31].each do |days|
    it "reports #{days} credited days without a percentage or safety target" do
      send_heartbeat(start, mode: "permissive")
      host.update!(reporting_started_at: (start - days.days).beginning_of_day)
      days.times { |n| host.host_reporting_days.create!(observed_on: start.to_date - n - 1, credited_microseconds: 86_400_000_000) }
      expect(readiness).to include(status: "observed", band: nil, reporting_days: days.to_f, capture_continuity: "unknown", target_days: nil)
    end
  end

  private

  def host
    Host.find_by!(external_id: "reporting-host")
  end

  def credit
    host.host_reporting_days.sum(:credited_microseconds).fdiv(1_000_000)
  end

  def readiness
    HostEnforcingReadiness.call(host, at: @received_at || start)
  end

  def payload(observed_at, boot: "boot-1", mode: "enforcing")
    { "schema_version" => 2, "agent" => { "version" => "test" }, "host_observed_at" => observed_at.iso8601(9),
      "host" => { "id" => "reporting-host", "hostname" => "reporting", "boot_id" => boot,
        "selinux" => { "enforcement" => mode } } }
  end

  def send_heartbeat(observed_at, received_at: observed_at, boot: "boot-1", mode: "enforcing", accepted: true)
    @received_at = received_at
    travel_to(received_at, with_usec: true) do
      post "/api/v1/heartbeat", params: payload(observed_at, boot: boot, mode: mode).to_json, headers: headers
      expect(response).to have_http_status(accepted ? :accepted : :unprocessable_content)
    end
  end

  def raw_event(at, category: "avc", transition: nil)
    host.raw_events.create!(organization: organization, agent_installation: host.agent_installations.sole,
      audit_timestamp: at, audit_sequence: RawEvent.count + 1, boot_id: "boot-1", completion_reason: "eoe",
      evidence_digest: "retained-test-evidence", agent_received_at: start, server_received_at: start,
      category: category, transition_type: transition, schema_version: 4)
  end

  def cleanup
    Occurrence.delete_all
    NormalizedDenial.delete_all
    IssueDispositionChange.delete_all
    Issue.delete_all
    RawAuditRecord.delete_all
    RawEvent.delete_all
    HostSnapshotObservation.delete_all
    HostSnapshot.delete_all
    AgentInstallation.delete_all
    Host.delete_all
    Organization.delete_all
  end
end
