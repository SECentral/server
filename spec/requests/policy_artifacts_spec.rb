require "rails_helper"

RSpec.describe "Policy artifact ingestion API", type: :request do
  before do
    PolicyFact.delete_all
    PolicyArtifact.delete_all
    HostSnapshotObservation.delete_all
    HostSnapshot.delete_all
    AgentInstallation.delete_all
    Host.delete_all
    Organization.delete_all
    Organization.create!(name: "policy-artifacts")
  end

  let(:bytes) { "exact loaded policy artifact" }
  let(:identity) { "sha256:#{Digest::SHA256.hexdigest(bytes)}" }
  let(:headers) { { "CONTENT_TYPE" => "application/json", "Authorization" => "Bearer test-ingestion-key" } }

  it "requests a missing exact artifact, verifies and retains it once" do
    post "/api/v1/heartbeat", params: heartbeat(identity, "host-1").to_json, headers: headers

    expect(response).to have_http_status(:accepted)
    expect(response.parsed_body).to include("policy_artifact_required" => true, "policy_identity" => identity)

    upload_policy(identity, bytes, "host-1")
    expect(response).to have_http_status(:created)
    expect(PolicyArtifact.count).to eq(1)
    expect(PolicyArtifact.first).to have_attributes(policy_identity: identity, artifact: bytes, artifact_size: bytes.bytesize, source_host_id: "host-1")

    upload_policy(identity, bytes, "host-1")
    expect(response).to have_http_status(:created)
    expect(PolicyArtifact.count).to eq(1)
  end

  it "does not request an artifact that is already retained" do
    PolicyArtifact.create!(policy_identity: identity, artifact: bytes, artifact_size: bytes.bytesize)

    post "/api/v1/heartbeat", params: heartbeat(identity, "host-1").to_json, headers: headers

    expect(response).to have_http_status(:accepted)
    expect(response.parsed_body).to eq({})
    expect(PolicyArtifact.count).to eq(1)
  end

  it "rejects bytes whose digest does not match the reported identity" do
    post "/api/v1/heartbeat", params: heartbeat(identity, "host-1").to_json, headers: headers
    upload_policy(identity, "different bytes", "host-1")

    expect(response).to have_http_status(:unprocessable_content)
    expect(PolicyArtifact.count).to eq(0)
  end

  it "requires the authenticated host to have reported that exact policy identity" do
    other = "sha256:" + "b" * 64
    post "/api/v1/heartbeat", params: heartbeat(other, "host-2").to_json, headers: headers
    upload_policy(identity, bytes, "host-2")

    expect(response).to have_http_status(:conflict)
    expect(PolicyArtifact.count).to eq(0)
  end

  it "does not request an artifact when policy identity is unavailable" do
    post "/api/v1/heartbeat", params: heartbeat(nil, "host-1").to_json, headers: headers

    expect(response).to have_http_status(:accepted)
    expect(response.parsed_body).to eq({})
  end

  it "rejects oversized policy artifacts" do
    post "/api/v1/heartbeat", params: heartbeat(identity, "host-1").to_json, headers: headers
    upload_policy(identity, "x" * (PolicyArtifact::MAX_BYTES + 1), "host-1")

    expect(response).to have_http_status(:content_too_large)
    expect(PolicyArtifact.count).to eq(0)
  end

  private

  def heartbeat(policy_identity, host_id)
    selinux = { "enabled" => true, "enforcement" => "enforcing" }
    selinux["policy_identity"] = policy_identity if policy_identity
    {
      "schema_version" => 2, "agent" => { "version" => "test" },
      "host_observed_at" => Time.current.iso8601,
      "host" => { "id" => host_id, "hostname" => host_id, "boot_id" => "boot-#{host_id}", "platform" => {}, "selinux" => selinux }
    }
  end

  def upload_policy(policy_identity, body, host_id)
    put "/api/v1/policy-artifacts/#{policy_identity}", params: body,
      headers: { "CONTENT_TYPE" => "application/octet-stream", "Authorization" => "Bearer test-ingestion-key", "X-SECentral-Host-ID" => host_id }
  end
end
