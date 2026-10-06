require "rails_helper"

RSpec.describe "Validated SELinux port writes", type: :request do
  include ActiveJob::TestHelper
  let(:organization) { Organization.create!(name: "port-transition") }
  let(:base) { Time.current.change(usec: 0) - 30.seconds }
  let(:identity) { "sha256:#{Digest::SHA256.hexdigest('original bytes')}" }
  let(:headers) { { "CONTENT_TYPE" => "application/json", "Authorization" => "Bearer test-ingestion-key" } }
  let(:host) { Host.find_by!(organization: organization, external_id: "port-host") }
  let(:add) { "resrc=port op=add lport=23451 proto=6 tcontext=system_u:object_r:http_port_t:s0 res=success" }

  before do
    clear_records
    organization
  end
  after { clear_records }

  def clear_records
    clear_enqueued_jobs
    Occurrence.delete_all
    NormalizedDenial.delete_all
    PolicyFact.delete_all
    PolicyArtifact.delete_all
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

  ["add", "modify", "delete"].each do |operation|
    it "masks #{operation} port/identity trust without discarding boolean, enforcement or AVC target evidence" do
      checkpoint(0)
      old = HostSnapshot.last
      fields = operation == "delete" ? "resrc=port op=delete lport=23451 proto=6 res=success" : add.sub("op=add", "op=#{operation}")
      transition = administrative(2, 10, fields)
      expect(transition.transition_type).to eq("port_change")
      expect([Issue.count, Occurrence.count, PolicyFact.count]).to eq([0, 0, 0])
      expect(host.port_inventory_for).to eq("status" => "unknown", "mappings" => [])
      expect(host.current_policy_identity).to be_nil
      expect(host.enforcement_for).to eq("enforcing")
      comparison = HostConfigurationComparison.call(host)
      expect(comparison.selinux.dig("policy", "port_inventory", "status")).to eq("unknown")
      expect(comparison.selinux["boolean_status"]).to eq("observed")
      occurrence = avc(3, 11)
      raw = occurrence.raw_event
      expect(occurrence.host_snapshot).to eq(old)
      expect(raw.checkpoint_invalidated_fields).to contain_exactly("ports", "policy_identity")
      expect(raw.checkpoint_policy_identity).to be_nil
      expect(raw.checkpoint_enforcement_mode).to eq("enforcing")
      expect(occurrence.host_snapshot.details.dig("selinux", "booleans", 0, "current")).to be(false)
      expect(occurrence.normalized_denial.target_type).to eq("http_port_t")
      expect(occurrence.normalized_denial.details["permissive"]).to be(false)
      PolicyFactRequest.for_issue(occurrence.issue)
      expect(PolicyFact.count).to eq(0)
      expect(PolicyEvaluation.call(occurrence.issue)[:occurrence_evaluations].sole).to include(status: "unavailable", policy_identity: [], checkpoint_enforcement_mode: "enforcing")
      checkpoint(4, type: "http_port_t", digest: "sha256:#{'b' * 64}")
      later = avc(5, 12, observed: 4)
      expect(later.raw_event.checkpoint_invalidated_fields).to eq([])
      expect(later.raw_event.checkpoint_port_inventory["status"]).to eq("observed")
      expect(host.reload.port_inventory_for["status"]).to eq("observed")
      expect(raw.reload.checkpoint_port_inventory["status"]).to eq("unknown")
      item = HostSelinuxActivity.new(host).detail(transition.id)
      expect(item[:port_changes].sole).to include("operation" => operation, "boundary_established" => true)
      expect(item[:window_occurrences].sole[:id]).to eq(occurrence.id)
      expect(item[:window_avc_count]).to eq(1)
    end
  end

  it "independently repairs reordered delivery, preserves serial order and deduplicates replay" do
    checkpoint(0)
    before = avc(2, 9)
    after = avc(2, 11)
    snapshot = after.host_snapshot
    first = administrative(2, 10, add)
    expect(administrative(2, 10, add).id).to eq(first.id)
    expect(RawEvent.where(transition_type: "port_change").count).to eq(1)
    expect(before.raw_event.reload.checkpoint_invalidated_fields).to eq([])
    expect(after.raw_event.reload.checkpoint_invalidated_fields).to contain_exactly("ports", "policy_identity")
    ProcessRawEvent.call(after.raw_event)
    expect(after.reload.host_snapshot).to eq(snapshot)
    expect(after.policy_identity).to be_nil
  end

  it "protects events delivered before port administration using durable trust masks" do
    checkpoint(0)
    occurrence = avc(3, 11, mask: %w[policy_identity ports])
    expect(occurrence.policy_identity).to be_nil
    expect(host.current_policy_identity).to be_nil
    expect(host.port_inventory_for["status"]).to eq("unknown")
  end

  it "combines overlapping dimensions without overwriting an earlier mask" do
    checkpoint(0)
    occurrence = avc(4, 12, mask: ["enforcement"])
    administrative(2, 10, add)
    administrative(3, 11, "enforcing=0 old_enforcing=1 enabled=1 old-enabled=1 lsm=selinux res=1", code: 1404)
    expect(occurrence.raw_event.reload.checkpoint_invalidated_fields).to contain_exactly("enforcement", "ports", "policy_identity")
    expect(occurrence.reload.host_snapshot).to be_present
    administrative(3, 13, "res=1", code: 1403)
    expect(occurrence.reload.host_snapshot).to be_nil
    expect(occurrence.raw_event.reload.checkpoint_invalidated_fields).to contain_exactly("enforcement", "ports", "policy_identity")
  end

  ["res=failed", "proto=bad", "lport=65536", "lport=23453-23451", "proto=6 proto=17", "proto=6 proto=", 'proto=6 proto="broken', "op=unsupported"].each do |bad|
    it "retains malformed/failed port history (#{bad}) without a boundary" do
      checkpoint(0)
      key = bad.split("=").first
      fields = add.sub(/#{key}=\S+/, bad)
      raw = administrative(2, 10, fields)
      expect(raw.transition_type).to be_nil
      expect(host.port_inventory_for["status"]).to eq("observed")
      expect(avc(3, 11).raw_event.checkpoint_invalidated_fields).to eq([])
    end
  end

  it "rejects unrelated semanage families and never uses command arguments as authority" do
    checkpoint(0)
    fields = add.sub("resrc=port", "resrc=fcontext") + ' comm="resrc=port op=add lport=23451 proto=6"'
    submit(2, 10, fields, "selinux_administrative", 2312)
    expect(response).to have_http_status(:unprocessable_content)
    expect(RawEvent.count).to eq(0)
  end

  it "does not correlate across boots, backfill a checkpoint tie, or synthesize missing changes" do
    checkpoint(0)
    administrative(2, 10, add, boot: "other")
    expect(avc(3, 11).raw_event.checkpoint_invalidated_fields).to eq([])
    checkpoint(4, type: "http_port_t")
    expect(RawEvent.where(transition_type: "port_change").count).to eq(1)
    expect(avc(4, 12, observed: 4).host_snapshot).to be_nil
  end

  it "keeps historical artifacts/facts and reuses them when exact original bytes return" do
    bytes = "original bytes"
    artifact = PolicyArtifact.create!(policy_identity: identity, artifact: bytes, artifact_size: bytes.bytesize)
    fact = PolicyFact.create!(policy_identity: identity, query_kind: "allow", source_type: "httpd_t", target_type: "http_port_t", object_class: "tcp_socket", permission: "name_connect", status: "no_match", evaluator_version: "test")
    checkpoint(0)
    administrative(2, 10, add)
    checkpoint(4)
    expect(JSON.parse(response.body)).to eq({})
    occurrence = avc(5, 12, observed: 4)
    PolicyFactRequest.for_issue(occurrence.issue)
    expect(PolicyFact.sole).to eq(fact)
    expect(PolicyArtifact.sole).to eq(artifact)
  end

  def checkpoint(offset, type: "unreserved_port_t", digest: identity)
    host_data = { "id" => "port-host", "boot_id" => "boot-1", "selinux" => { "enforcement" => "enforcing", "policy_identity" => digest,
      "boolean_status" => "observed", "booleans" => [{ "name" => "nis_enabled", "current" => false, "status" => "observed" }],
      "policy" => { "port_inventory" => { "status" => "observed", "mappings" => [{ "protocol" => "tcp", "type" => type, "ports" => [{ "start" => 23451, "end" => 23451 }] }] } } } }
    post "/api/v1/heartbeat", params: { schema_version: 2, agent: { version: "test" }, host_observed_at: (base + offset).iso8601(6), host: host_data }.to_json, headers: headers
    expect(response).to have_http_status(:accepted)
  end

  def administrative(offset, serial, fields, code: 2312, boot: "boot-1")
    submit(offset, serial, code == 2312 ? "pid=1 uid=0 auid=0 ses=3 msg='#{fields}'" : fields, "selinux_administrative", code, boot: boot)
    expect(response).to have_http_status(:accepted)
    RawEvent.find_by!(boot_id: boot, audit_sequence: serial)
  end

  def avc(offset, serial, observed: 0, mask: [])
    fields = 'avc: denied { name_connect } for comm="httpd" dest=23451 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:http_port_t:s0 tclass=tcp_socket permissive=0'
    submit(offset, serial, fields, "avc", 1400, observed: observed, mask: mask)
    expect(response).to have_http_status(:accepted)
    RawEvent.find_by!(boot_id: "boot-1", audit_sequence: serial).occurrences.sole
  end

  def submit(offset, serial, fields, category, code, boot: "boot-1", observed: nil, mask: [])
    time = (base + offset).iso8601(6)
    names = { 2312 => "USER_MAC_CONFIG_CHANGE", 1400 => "AVC", 1403 => "MAC_POLICY_LOAD", 1404 => "MAC_STATUS" }
    record = { position: 0, type: code, type_name: names.fetch(code), timestamp: time, sequence: serial, payload: Base64.strict_encode64("audit(#{(base + offset).to_f}:#{serial}): #{fields}") }
    payload = { schema_version: 4, agent: { version: "test" }, host_id: "port-host", boot_id: boot, checkpoint_invalidated_fields: mask,
      host_observed_at: observed && (base + observed).iso8601(6), events: [{ category: category, audit_event: { timestamp: time, sequence: serial }, agent_received_at: time, completion_reason: "timeout", records: [record] }] }
    post "/api/v1/events", params: payload.to_json, headers: headers
  end
end
