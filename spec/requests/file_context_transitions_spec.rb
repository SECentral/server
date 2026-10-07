require "rails_helper"

RSpec.describe "Validated expected-label mapping boundaries", type: :request do
  include ActiveJob::TestHelper
  let(:organization) { Organization.create!(name: "mapping-boundary") }
  let(:base) { Time.current.change(usec: 0) - 60.seconds }
  let(:bytes) { "unchanged mapping policy bytes" }
  let(:identity) { "sha256:#{Digest::SHA256.hexdigest(bytes)}" }
  let(:host) { Host.find_by!(external_id: "mapping-host") }
  let(:headers) { { "CONTENT_TYPE" => "application/json", "Authorization" => "Bearer test-ingestion-key" } }
  let(:expression) { "/srv/test(/.*)?" }
  before { cleanup; organization }
  after { cleanup }

  def cleanup
    clear_enqueued_jobs
    Occurrence.delete_all; NormalizedDenial.delete_all; PolicyFact.delete_all; PolicyArtifact.delete_all
    IssueDispositionChange.delete_all; Issue.delete_all; RawAuditRecord.delete_all; RawEvent.delete_all
    HostSnapshotObservation.delete_all; HostSnapshot.delete_all; AgentInstallation.delete_all; Host.delete_all; Organization.delete_all
  end

  %w[add modify delete].each do |operation|
    it "invalidates only mappings on #{operation}, retaining actual labels and exact-P facts" do
      checkpoint(0)
      original = HostSnapshot.last
      artifact = PolicyArtifact.create!(policy_identity: identity, artifact: bytes, artifact_size: bytes.bytesize)
      fact = PolicyFact.create!(policy_identity: identity, query_kind: "allow", source_type: "httpd_t", target_type: "var_t", object_class: "file", permission: "entrypoint", status: "no_match", evaluator_version: "test")
      transition = mapping(2, 10, operation)
      expect(transition.transition_type).to eq("file_context_change")
      expect([Occurrence.count, Issue.count]).to eq([0, 0])
      expect(host.file_context_mappings_for["status"]).to eq("unknown")
      expect(host.current_policy_identity).to eq(identity)
      expect(host.enforcement_for).to eq("enforcing")
      occurrence = avc(3, 11)
      expect(occurrence.host_snapshot).to eq(original)
      expect(occurrence.raw_event.checkpoint_invalidated_fields).to eq(["file_context_mappings"])
      expect(occurrence.normalized_denial.target_type).to eq("var_t")
      expect(occurrence.normalized_denial.target_context).to eq("unconfined_u:object_r:var_t:s0")
      expect(occurrence.normalized_denial.details.dig("target_evidence", "filesystem_paths")).to eq(["/srv/test/file"])
      expect(occurrence.normalized_denial.details.dig("syscall_evidence", 0, "exit")).to eq("-13")
      expect(PolicyEvaluation.call(occurrence.issue)[:occurrence_evaluations].sole).to include(status: "evaluated", policy_identity: [identity])
      # Preserve the original later inspection, but do not use it as window labeling evidence.
      observation = { "kind" => "expected_context", "path" => "/srv/test/file", "object_class" => "file", "file_type" => "file", "status" => "resolved", "resolver" => "matchpathcon", "observed_at" => (base+3.1).iso8601(6), "expected_context" => "system_u:object_r:httpd_sys_content_t:s0" }
      occurrence.raw_event.update!(file_context_observations: [observation])
      projected = OccurrenceDetailSerializer.call(occurrence)
      expect(projected.dig(:raw_event, :file_context_observations, 0, "status")).to eq("unavailable")
      expect(occurrence.raw_event.reload.file_context_observations.sole).to eq(observation)
      intelligence = IssueIntelligence.call(occurrence.issue)
      expect(intelligence[:expected_context_observations].sole["status"]).to eq("unavailable")
      expect(IssueDiagnosis.call(occurrence.issue, intelligence: intelligence)[:kind]).not_to eq("file_context_mismatch")
      checkpoint(4, type: "httpd_sys_content_t")
      expect(JSON.parse(response.body)).to eq({})
      later = avc(5, 12, observed: 4)
      expect(later.raw_event.checkpoint_invalidated_fields).to eq([])
      expect(host.reload.file_context_mappings_for["status"]).to eq("observed")
      expect(occurrence.raw_event.reload.checkpoint_trust.file_context_mappings["status"]).to eq("unknown")
      expect(PolicyArtifact.sole).to eq(artifact)
      expect(PolicyFact.sole).to eq(fact)
      item = HostSelinuxActivity.new(host).detail(transition.id)
      expect(item[:file_context_changes].sole).to include("expression" => expression, "operation" => operation, "state_change_established" => false, "boundary_established" => true)
      expect(item[:window_occurrences].sole[:id]).to eq(occurrence.id)
    end
  end

  it "corrects reordered delivery and idempotent replay without deleting unrelated association" do
    checkpoint(0)
    before = avc(2, 9)
    after = avc(2, 11)
    original = after.host_snapshot
    first = mapping(2, 10, "add")
    expect(mapping(2, 10, "add").id).to eq(first.id)
    expect(before.raw_event.reload.checkpoint_invalidated_fields).to eq([])
    expect(after.raw_event.reload.checkpoint_invalidated_fields).to eq(["file_context_mappings"])
    ProcessRawEvent.call(after.raw_event)
    expect(after.reload.host_snapshot).to eq(original)
  end

  it "does not reconcile partial/missing inventory and does not backfill later complete data" do
    checkpoint(0)
    transition = mapping(2, 10, "add")
    checkpoint(3, status: "partial")
    item = HostSelinuxActivity.new(host).detail(transition.id)
    expect(item.dig(:reconciliation, :status)).to eq("pending")
    expect(item.dig(:reconciliation, :unreconciled_fields)).to eq(["file_context_mappings"])
    window = avc(4, 11, observed: 3, mask: ["file_context_mappings"])
    checkpoint(5)
    expect(HostSelinuxActivity.new(host.reload).detail(transition.id).dig(:reconciliation, :status)).to eq("reconciled")
    expect(window.raw_event.reload.checkpoint_invalidated_fields).to eq(["file_context_mappings"])
    expect(avc(6, 12, observed: 5).raw_event.checkpoint_invalidated_fields).to eq([])
  end

  ["res=failed", "res=unknown", "ftype=unknown", "op=modify-equal", 'tglob="relative"', 'tglob="/srv/test" tglob="/srv/other"', "tcontext=invalid"].each do |invalid|
    it "retains #{invalid} as non-boundary history" do
      checkpoint(0)
      raw = mapping(2, 10, "add", replace: invalid)
      expect(raw.transition_type).to be_nil
      expect(avc(3, 11).raw_event.checkpoint_invalidated_fields).to eq([])
    end
  end

  it "composes with all existing boundaries without reconstructing imports or crossing boots" do
    checkpoint(0)
    mapping(2, 10, "add", boot: "other")
    expect(avc(3, 11).raw_event.checkpoint_invalidated_fields).to eq([])
    mapping(4, 12, "add")
    send_event(5, 13, 1404, "enforcing=0 old_enforcing=1 enabled=1 old-enabled=1 lsm=selinux res=1")
    send_event(6, 14, 1405, "bool=nis_enabled val=1 old_val=0")
    send_event(7, 15, 1403, "res=1")
    window = avc(8, 16)
    expect(window.raw_event.checkpoint_invalidated_fields).to eq(CheckpointTrust::FIELDS.sort)
    expect(window.host_snapshot).to be_nil
    checkpoint(9, type: "httpd_sys_content_t")
    expect(RawEvent.where(transition_type: "file_context_change").count).to eq(2)
    expect(avc(10, 17, observed: 9).raw_event.checkpoint_invalidated_fields).to eq([])
  end

  it "observes missing-event mapping drift without synthetic user administration" do
    checkpoint(0)
    checkpoint(4, type: "httpd_sys_content_t")
    expect(RawEvent.count).to eq(0)
    expect(host.file_context_mappings_for["mappings"].sole["context"]).to include("httpd_sys_content_t")
  end

  def checkpoint(offset, type: "var_t", status: "observed")
    context = { "pattern" => expression, "file_type" => "all files", "context" => "system_u:object_r:#{type}:s0", "provenance" => "custom" }
    data = { "id" => "mapping-host", "boot_id" => "boot-1", "selinux" => { "enabled" => true, "enforcement" => "enforcing", "policy_identity" => identity,
      "boolean_status" => "observed", "booleans" => [{ "name" => "nis_enabled", "status" => "observed", "current" => false }],
      "policy" => { "port_inventory" => { "status" => "observed", "mappings" => [] }, "file_context_mappings_status" => status,
        "file_contexts" => [context], "local_file_context_mappings" => [context], "file_context_equivalences" => [] } } }
    post "/api/v1/heartbeat", params: { schema_version: 2, agent: { version: "test" }, host_observed_at: (base+offset).iso8601(6), host: data }.to_json, headers: headers
    expect(response).to have_http_status(:accepted)
  end
  def mapping(offset, serial, operation, replace: nil, boot: "boot-1")
    fields = "resrc=fcontext op=#{operation} tglob=\"#{expression}\" ftype=any"
    fields += " tcontext=system_u:object_r:httpd_sys_content_t:" unless operation == "delete"
    fields += " res=success"
    fields = fields.sub(/#{replace.split('=').first}=(?:"[^"]*"|\S+)/, replace) if replace
    send_event(offset, serial, 2312, "pid=1 uid=0 auid=0 ses=29 msg='#{fields} comm=\"semanage\"'", boot: boot)
  end
  def avc(offset, serial, observed: 0, mask: [])
    raw = send_event(offset, serial, 1400, 'avc: denied { entrypoint } for comm="id" path="/srv/test/file" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:var_t:s0 tclass=file permissive=0', observed: observed, mask: mask)
    raw.occurrences.sole
  end
  def send_event(offset, serial, code, fields, boot: "boot-1", observed: nil, mask: [])
    time=(base+offset).iso8601(6)
    record={ position: 0, type: code, type_name: { 2312=>"USER_MAC_CONFIG_CHANGE", 1400=>"AVC", 1403=>"MAC_POLICY_LOAD", 1404=>"MAC_STATUS", 1405=>"MAC_CONFIG_CHANGE" }.fetch(code), timestamp: time, sequence: serial, payload: Base64.strict_encode64("audit(#{(base+offset).to_f}:#{serial}): #{fields}") }
    records=[record]
    records << record.merge(position: 1, type: 1300, type_name: "SYSCALL", payload: Base64.strict_encode64("audit(#{(base+offset).to_f}:#{serial}): syscall=59 success=no exit=-13")) if code==1400
    post "/api/v1/events", params: { schema_version: 4, agent: { version: "test" }, host_id: "mapping-host", boot_id: boot, host_observed_at: observed && (base+observed).iso8601(6), checkpoint_invalidated_fields: mask,
      events: [{ category: code==1400 ? "avc" : "selinux_administrative", audit_event: { timestamp: time, sequence: serial }, agent_received_at: time, completion_reason: "timeout", records: records }] }.to_json, headers: headers
    expect(response).to have_http_status(:accepted)
    RawEvent.find_by!(boot_id: boot, audit_sequence: serial)
  end
end
