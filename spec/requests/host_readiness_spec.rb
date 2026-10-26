require "rails_helper"

RSpec.describe "Host detail enforcing readiness", type: :request do
  include ActiveSupport::Testing::TimeHelpers

  let(:at) { Time.utc(2026, 10, 13, 12) }
  let(:organization) { Organization.create!(name: "Readiness API") }

  around { |example| travel_to(at) { example.run } }
  before { cleanup; organization; sign_in_operator }
  after { cleanup }

  it "projects credited reporting duration without a readiness score or target" do
    host = reporting_host(days: 12)
    get "/api/v1/hosts/#{host.id}"
    expect(response).to have_http_status(:ok)
    result = JSON.parse(response.body).dig("host", "enforcing_readiness")
    expect(result).to include("status" => "observed", "reason" => nil, "band" => nil,
      "target_days" => nil, "credited_seconds" => 12 * 86_400, "reporting_days" => 12.0,
      "capture_continuity" => "unknown", "latest_avc_at" => nil)
    expect(result["explanation"]).to include("12.0 days", "Audit capture continuity is unknown", "not continuous observation", "does not establish suitability")
    expect(JSON.parse(response.body).dig("host", "reporting_observations")).to eq(result)
    expect(result).not_to have_key("probability")
  end

  it "qualifies already-enforcing hosts without setting their progress to 100%" do
    host = reporting_host(days: 12, mode: "enforcing")
    result = HostSerializer.call(host, include_snapshot: true).fetch(:enforcing_readiness)
    expect(result).to include(band: nil, reporting_days: 12.0)
    expect(result[:explanation]).not_to include("%", "target")
    get "/api/v1/hosts/#{host.id}"
    expect(JSON.parse(response.body).dig("host", "enforcing_readiness", "band")).to be_nil
    get "/api/v1/hosts"
    expect(JSON.parse(response.body).fetch("hosts").first).not_to have_key("enforcing_readiness")
  end

  it "returns reason-specific Unknown for untracked legacy history without inventing time" do
    host = organization.hosts.create!(external_id: "legacy")
    get "/api/v1/hosts/#{host.id}"
    result = JSON.parse(response.body).dig("host", "enforcing_readiness")
    expect(result).to include("status" => "unknown", "band" => nil, "credited_seconds" => nil,
      "reporting_days" => nil, "reason" => "reporting_not_tracked", "capture_continuity" => "unknown")
    expect(result["explanation"]).to include("duration has not yet been tracked", "cannot establish that enforcing mode is safe")
  end

  it "withholds an older band when evidence becomes stale despite fresh receipt-based liveness" do
    host = reporting_host(days: 12)
    host.update!(reporting_observed_at: at - 15.minutes, reporting_received_at: at - 15.minutes, last_seen_at: at)
    get "/api/v1/hosts/#{host.id}"
    result = JSON.parse(response.body).dig("host", "enforcing_readiness")
    expect(result).to include("status" => "unknown", "reason" => "reporting_stale", "band" => nil, "credited_seconds" => nil)
    expect(result["explanation"]).to include("reporting observation is stale")
    expect(result["explanation"]).not_to include("40–59%")
  end

  it "recalculates late and recent AVCs using their original day and preserves all evidence" do
    host = reporting_host(days: 12)
    late = avc(host, at - 2.days)
    get "/api/v1/hosts/#{host.id}"
    result = JSON.parse(response.body).dig("host", "enforcing_readiness")
    expect(result).to include("band" => nil, "credited_seconds" => 86_400, "reporting_days" => 1.0)
    expect(result["explanation"]).not_to include("The last recorded AVC's day")
    recent = avc(host, at)
    get "/api/v1/hosts/#{host.id}"
    expect(JSON.parse(response.body).dig("host", "enforcing_readiness", "credited_seconds")).to eq(0)
    expect(RawEvent.where(id: [late.id, recent.id]).count).to eq(2)
    expect(host.host_reporting_days.sum(:credited_microseconds)).to eq(12 * 86_400_000_000)
  end

  it "explains small nonzero duration and non-credited older reporting without JavaScript rounding" do
    host = reporting_host(days: 0)
    host.host_reporting_days.find_by!(observed_on: at.to_date).update!(credited_microseconds: 300_000_000)
    host.current_state_observation.update!(first_observed_at: at - 10.days)
    get "/api/v1/hosts/#{host.id}"
    result = JSON.parse(response.body).dig("host", "enforcing_readiness")
    expect(result).to include("credited_seconds" => 300, "reporting_days" => 0.0, "band" => nil)
    expect(result["explanation"]).to include("less than 0.1 days")
    expect(result["explanation"]).not_to include("Older reporting was not credited.")
  end

  it "keeps readiness within operator authentication, not ingestion-key authorization" do
    host = reporting_host(days: 12)
    sign_out_operator
    get "/api/v1/hosts/#{host.id}", headers: { "Authorization" => "Bearer test-ingestion-key" }
    expect(response).to have_http_status(:unauthorized)
    expect(response.body).not_to include("enforcing_readiness")
  end

  %w[reporting_time_unknown enforcement_unavailable checkpoint_unavailable checkpoint_boot_mismatch denial_time_unavailable].each do |reason|
    it "projects a reason-specific #{reason} with no numeric fallback" do
      host = reporting_host(days: 12)
      case reason
      when "reporting_time_unknown" then host.update!(reporting_sample_status: "timing_unknown")
      when "enforcement_unavailable" then host.update!(reporting_sample_status: "ineligible")
      when "checkpoint_unavailable" then HostSnapshotObservation.where(host_id: host.id).delete_all
      when "checkpoint_boot_mismatch" then host.update!(reporting_boot_id: "different-boot")
      when "denial_time_unavailable" then avc(host, at + 1.hour)
      end
      get "/api/v1/hosts/#{host.id}"
      result = JSON.parse(response.body).dig("host", "enforcing_readiness")
      expect(result).to include("status" => "unknown", "reason" => reason, "band" => nil,
        "credited_seconds" => nil, "reporting_days" => nil, "capture_continuity" => "unknown")
      expect(result["explanation"]).to start_with("Credited reporting duration is Unknown because")
      expect(result["explanation"]).not_to include("40–59%")
    end
  end

  private

  def reporting_host(days:, mode: "permissive")
    Heartbeat.call(organization: organization, payload: { "schema_version" => 2, "agent" => { "version" => "test" },
      "host_observed_at" => at.iso8601, "host" => { "id" => "readiness-host", "boot_id" => "boot", "selinux" => { "enforcement" => mode } } })
    host = Host.find_by!(external_id: "readiness-host")
    host.update!(reporting_started_at: (at - days.days).beginning_of_day)
    days.times { |n| host.host_reporting_days.create!(observed_on: at.to_date - n - 1, credited_microseconds: 86_400_000_000) }
    host
  end

  def avc(host, original_time)
    host.raw_events.create!(organization: organization, agent_installation: host.agent_installations.sole,
      audit_timestamp: original_time, audit_sequence: RawEvent.count + 1, boot_id: "boot", schema_version: 4,
      category: "avc", completion_reason: "eoe", evidence_digest: "retained-fixture", agent_received_at: at, server_received_at: at)
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
