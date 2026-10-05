require "rails_helper"

RSpec.describe "Heartbeats API", type: :request do
  before do
    cleanup_database
    organization
  end
  after { cleanup_database }

  let(:organization) { Organization.create!(name: "Heartbeat organization") }
  let(:headers) { { "CONTENT_TYPE" => "application/json", "Authorization" => "Bearer test-ingestion-key" } }

  it "records a host heartbeat and metadata snapshot" do
    post "/api/v1/heartbeat", params: heartbeat.to_json, headers: headers

    expect(response).to have_http_status(:accepted)
    expect(installation.reload.agent_version).to eq("0.2.0")
    expect(installation.last_seen_at).to be_present
    expect(installation.bound_host.hostname).to eq("alma-01")
    expect(installation.bound_host.last_seen_at).to be_present
    expect(HostSnapshot.count).to eq(1)
    expect(HostSnapshotObservation.count).to eq(1)
    expect(HostSnapshot.last.details.dig("selinux", "booleans")).to eq([
      { "name" => "httpd_can_network_connect", "current" => true, "default" => false, "status" => "observed" }
    ])
  end

  it "rejects missing ingestion keys" do
    post "/api/v1/heartbeat", params: heartbeat.to_json, headers: { "CONTENT_TYPE" => "application/json" }

    expect(response).to have_http_status(:unauthorized)
  end

  it "records different hosts with the same ingestion key" do
    post "/api/v1/heartbeat", params: heartbeat.to_json, headers: headers
    second = heartbeat.deep_dup
    second["host"]["id"] = "host-2"
    second["host"]["hostname"] = "alma-02"
    post "/api/v1/heartbeat", params: second.to_json, headers: headers

    expect(response).to have_http_status(:accepted)
    expect(Host.count).to eq(2)
    expect(AgentInstallation.count).to eq(2)
  end

  it "extends one epoch for repeated identical heartbeat state" do
    post "/api/v1/heartbeat", params: heartbeat.to_json, headers: headers
    first_observation = HostSnapshotObservation.last
    repeated = heartbeat.deep_dup
    repeated["host_observed_at"] = "2026-09-19T10:05:00.000000Z"
    post "/api/v1/heartbeat", params: repeated.to_json, headers: headers

    expect(HostSnapshot.count).to eq(1)
    expect(HostSnapshotObservation.count).to eq(1)
    expect(first_observation.reload).to have_attributes(
      first_observed_at: Time.iso8601("2026-09-19T10:00:00Z"),
      last_observed_at: Time.iso8601("2026-09-19T10:05:00Z")
    )
  end

  it "records A to B to A as three epochs referencing two states" do
    post "/api/v1/heartbeat", params: heartbeat.to_json, headers: headers

    changed = heartbeat.deep_dup
    changed["host_observed_at"] = "2026-09-19T10:05:00.000000Z"
    changed["host"]["selinux"]["booleans"][0]["current"] = false
    post "/api/v1/heartbeat", params: changed.to_json, headers: headers

    returned = heartbeat.deep_dup
    returned["host_observed_at"] = "2026-09-19T10:10:00.000000Z"
    post "/api/v1/heartbeat", params: returned.to_json, headers: headers

    expect(HostSnapshot.count).to eq(2)
    expect(HostSnapshotObservation.count).to eq(3)
    expect(HostSnapshotObservation.order(:first_received_at, :id).map(&:host_snapshot_id)).to eq([
      HostSnapshot.find_by!("details @> ?", { selinux: { booleans: [{ current: true }] } }.to_json).id,
      HostSnapshot.find_by!("details @> ?", { selinux: { booleans: [{ current: false }] } }.to_json).id,
      HostSnapshot.find_by!("details @> ?", { selinux: { booleans: [{ current: true }] } }.to_json).id
    ])
    expect(installation.reload.bound_host.current_snapshot.details.dig("selinux", "booleans", 0, "current")).to be(true)
  end

  private

  def heartbeat
    {
      "schema_version" => 2,
      "agent" => { "version" => "0.2.0" },
      "host_observed_at" => "2026-09-19T10:00:00.000000Z",
      "host" => {
        "id" => "host-1",
        "hostname" => "alma-01",
        "boot_id" => "boot-1",
        "platform" => { "os_id" => "almalinux", "os_version" => "9.3", "architecture" => "amd64" },
        "selinux" => { "enabled" => true, "enforcement" => "enforcing", "configured_policy_type" => "targeted", "kernel_policy_version" => 33,
          "booleans" => [{ "name" => "httpd_can_network_connect", "current" => true, "default" => false, "status" => "observed" }] }
      }
    }
  end

  def cleanup_database
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

  def installation
    Host.find_by!(external_id: "host-1").agent_installations.sole
  end
end
