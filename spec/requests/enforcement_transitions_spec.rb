require "rails_helper"

RSpec.describe "Runtime enforcement transition correctness", type: :request do
  include ActiveJob::TestHelper
  let(:organization) { Organization.create!(name: "enforcement-transition") }
  let(:base) { Time.current.change(usec: 0) - 30.seconds }
  let(:bytes) { "unchanged exact policy bytes" }
  let(:identity) { "sha256:#{Digest::SHA256.hexdigest(bytes)}" }
  let(:headers) { { "CONTENT_TYPE" => "application/json", "Authorization" => "Bearer test-ingestion-key" } }
  let(:host) { Host.find_by!(organization: organization, external_id: "mode-host") }

  before do
    organization
    PolicyArtifact.create!(policy_identity: identity, artifact: bytes, artifact_size: bytes.bytesize)
  end

  after do
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

  [["enforcing", "permissive", 1], ["permissive", "enforcing", 0]].each do |old_mode, new_mode, local_permissive|
    it "invalidates #{old_mode} host enforcement independently while preserving exact policy, booleans and AVC-local evidence" do
      checkpoint(0, old_mode)
      old = HostSnapshot.last
      fact = matching_fact
      transition = status(2, 10, old_mode, new_mode)
      expect(transition).to have_attributes(category: "selinux_administrative", transition_type: "enforcement_change")
      expect(transition.enforcement_changes.sole).to include("old_mode" => old_mode, "new_mode" => new_mode, "success" => true)
      expect([Occurrence.count, Issue.count, PolicyFact.count]).to eq([0, 0, 1])
      expect(host.enforcement_for).to eq("unknown")
      expect(host.current_policy_identity).to eq(identity)
      expect(HostSerializer.call(host, include_snapshot: true).dig(:selinux, :enforcement)).to eq("unknown")
      expect(HostConfigurationComparison.call(host).selinux["enforcement"]).to eq("unknown")
      expect(HostListQuery.new(filters: { enforcement: old_mode }).call.hosts).to be_empty

      occurrence = avc(3, 11, local_permissive, checkpoint_at: 0)
      expect(occurrence.host_snapshot).to eq(old)
      expect(occurrence.raw_event.checkpoint_invalidated_fields).to eq(["enforcement"])
      expect(occurrence.raw_event.checkpoint_enforcement_mode).to eq("unknown")
      expect(occurrence.normalized_denial.details["permissive"]).to eq(local_permissive == 1)
      result = PolicyEvaluation.call(occurrence.issue)[:occurrence_evaluations].sole
      expect(result).to include(checkpoint_enforcement_mode: "unknown", policy_identity: [identity],
        enforcement_mode: new_mode, permissive: local_permissive == 1, rule_state: "conditional_inactive")
      expect(PolicyFact.count).to eq(1)
      expect(PolicyFact.sole).to eq(fact)
      expect(IssueIntelligence.call(occurrence.issue).dig(:occurrence_time, :enforcement_distribution)).to eq("unknown" => 1)

      checkpoint(4, new_mode)
      expect(JSON.parse(response.body)).to eq({})
      later = avc(5, 12, local_permissive, checkpoint_at: 4)
      expect(later.host_snapshot).to eq(HostSnapshot.last)
      expect(later.raw_event.checkpoint_invalidated_fields).to eq([])
      expect(later.raw_event.checkpoint_enforcement_mode).to eq(new_mode)
      expect(host.reload.enforcement_for).to eq(new_mode)
      expect(host.current_policy_identity).to eq(identity)
      expect(PolicyArtifact.count).to eq(1)
      expect(occurrence.reload.host_snapshot).to eq(old)
      expect(occurrence.raw_event.reload.checkpoint_enforcement_mode).to eq("unknown")
    end
  end

  it "accepts the agent's scoped uncertainty before the administrative event arrives, then deduplicates replay" do
    checkpoint(0, "enforcing")
    matching_fact
    window = avc(3, 11, 1, checkpoint_at: 0, invalidated: ["enforcement"])
    expect(window.raw_event.checkpoint_enforcement_mode).to eq("unknown")
    expect(host.enforcement_for).to eq("unknown")
    expect(host.current_policy_identity).to eq(identity)
    first = status(2, 10, "enforcing", "permissive")
    second = status(2, 10, "enforcing", "permissive")
    expect(second.id).to eq(first.id)
    expect(RawEvent.where(transition_type: "enforcement_change").count).to eq(1)
    expect(window.reload.host_snapshot).to be_present
    expect(window.raw_event.reload.checkpoint_invalidated_fields).to eq(["enforcement"])
  end

  it "retracts only enforcement trust after delayed delivery and preserves serial ordering at timestamp ties" do
    checkpoint(0, "permissive")
    before = avc(2, 9, 1, checkpoint_at: 0)
    after = avc(2, 11, 0, checkpoint_at: 0)
    snapshot = after.host_snapshot
    status(2, 10, "permissive", "enforcing")
    expect(before.raw_event.reload.checkpoint_invalidated_fields).to eq([])
    expect(after.raw_event.reload.checkpoint_invalidated_fields).to eq(["enforcement"])
    expect(after.reload.host_snapshot).to eq(snapshot)
    ProcessRawEvent.call(after.raw_event)
    expect(after.reload.host_snapshot).to eq(snapshot)
    expect(after.normalized_denial.reload.details["enforcement_mode"]).to eq("enforcing")
  end

  ["res=0", "res=unknown", "", "res=1 success=no"].each do |result|
    it "retains #{result.presence || 'missing result'} history without establishing a boundary" do
      checkpoint(0, "enforcing")
      raw = status(2, 10, "enforcing", "permissive", result: result)
      expect(raw.transition_type).to be_nil
      expect(raw.raw_audit_records.first.payload).to include("enforcing=0 old_enforcing=1")
      expect(host.enforcement_for).to eq("enforcing")
      expect(avc(3, 11, 0, checkpoint_at: 0).raw_event.checkpoint_invalidated_fields).to eq([])
    end
  end

  it "retains equal-state and enablement/status shapes as non-boundary history" do
    checkpoint(0, "enforcing")
    equal = status(2, 10, "enforcing", "enforcing")
    disabled = status(3, 11, "enforcing", "permissive", enabled: "0")
    duplicate = status(4, 12, "enforcing", "permissive", result: "res=0 res=1")
    expect([equal, disabled, duplicate].map(&:transition_type)).to eq([nil, nil, nil])
    expect(RawEvent.count).to eq(3)
    expect(host.enforcement_for).to eq("enforcing")
    expect(Occurrence.count).to eq(0)
  end

  it "keeps AVC-local permissive evidence even without a policy checkpoint" do
    occurrence = avc(3, 11, 1, checkpoint_at: nil)
    result = PolicyEvaluation.call(occurrence.issue)[:occurrence_evaluations].sole
    expect(result).to include(status: "unavailable", enforcement_mode: "permissive", permissive: true,
      checkpoint_enforcement_mode: "unknown", policy_identity: [])
  end

  it "does not mistake a permissive-domain AVC for evidence that the whole host was permissive" do
    checkpoint(0, "enforcing")
    matching_fact
    occurrence = avc(3, 11, 1, checkpoint_at: 0)
    result = PolicyEvaluation.call(occurrence.issue)[:occurrence_evaluations].sole
    expect(result).to include(enforcement_mode: "permissive", checkpoint_enforcement_mode: "enforcing")
    expect(host.enforcement_for).to eq("enforcing")
  end

  it "does not correlate boundaries or checkpoint masks across boots" do
    checkpoint(0, "enforcing")
    status(2, 10, "enforcing", "permissive", boot: "other-boot")
    occurrence = avc(3, 11, 0, checkpoint_at: 0)
    expect(occurrence.raw_event.checkpoint_invalidated_fields).to eq([])
    expect(host.enforcement_for).to eq("enforcing")
  end

  it "does not synthesize a transition from a heartbeat-only mode difference" do
    checkpoint(0, "enforcing")
    checkpoint(4, "permissive")
    expect(RawEvent.count).to eq(0)
    expect(host.enforcement_for).to eq("permissive")
  end

  it "rejects stale full checkpoint publication without losing unchanged identity or requesting its artifact" do
    checkpoint(0, "enforcing")
    status(2, 10, "enforcing", "permissive")
    checkpoint(1, "enforcing")
    expect(JSON.parse(response.body)).to eq({})
    expect(HostSnapshot.count).to eq(1)
    expect(host.current_policy_identity).to eq(identity)
    expect(host.enforcement_for).to eq("unknown")
  end

  it "rejects unsupported/duplicated trust-mask fields at the protocol boundary" do
    [["unsupported"], ["enforcement", "enforcement"], "enforcement"].each do |fields|
      request = request_for(3, 11, "boot-1", [[1400, "AVC", avc_text(0)]], "avc", 0)
      request["checkpoint_invalidated_fields"] = fields
      post "/api/v1/events", params: request.to_json, headers: headers
      expect(response).to have_http_status(:unprocessable_content)
    end
    expect(RawEvent.count).to eq(0)
  end

  it "projects a mode-only unresolved interval even when policy checkpoint association remains valid" do
    checkpoint(0, "enforcing")
    transition = status(2, 10, "enforcing", "permissive")
    window = avc(3, 11, 1, checkpoint_at: 0)
    checkpoint(4, "permissive")
    sign_in_operator
    get "/api/v1/hosts/#{host.id}/selinux-activity/#{transition.id}"
    expect(response).to have_http_status(:ok)
    item = JSON.parse(response.body).fetch("item")
    expect(item).to include("transition_type" => "enforcement_change", "window_avc_count" => 1)
    expect(item["enforcement_changes"].sole).to include("old_mode" => "enforcing", "new_mode" => "permissive", "state_change_established" => true)
    expect(item["window_occurrences"].sole["id"]).to eq(window.id)
    expect(item.dig("reconciliation", "checkpoint", "policy_identity")).to eq(identity)
    get "/api/v1/hosts/#{host.id}/selinux-activity", params: { occurrence_id: window.id }
    expect(JSON.parse(response.body).fetch("items").sole["id"]).to eq(transition.id)
  end

  it "does not treat an enforcement-only transition as superseding a policy reconciliation" do
    checkpoint(0, "enforcing")
    request = request_for(2, 10, "boot-1", [[1403, "MAC_POLICY_LOAD", "res=1"]], "selinux_administrative")
    post "/api/v1/events", params: request.to_json, headers: headers
    policy = RawEvent.last
    status(3, 11, "enforcing", "permissive")
    checkpoint(4, "permissive")
    item = HostSelinuxActivity.new(host).page(event_id: policy.id).fetch(:items).sole
    expect(item.dig(:reconciliation, :status)).to eq("reconciled")
    expect(item.dig(:reconciliation, :next_transition)).to be_nil
  end

  def matching_fact
    PolicyFact.create!(policy_identity: identity, query_kind: "allow", source_type: "httpd_t", target_type: "user_home_t",
      object_class: "file", permission: "read", status: "matched", evaluator_version: "test",
      matching_rules: ["allow httpd_t user_home_type:file read; [ httpd_read_user_content ]:True"])
  end

  def checkpoint(offset, mode, boot: "boot-1")
    payload = { "schema_version" => 2, "agent" => { "version" => "test" }, "host_observed_at" => (base + offset).iso8601(6),
      "host" => { "id" => "mode-host", "hostname" => "mode-test", "boot_id" => boot,
        "selinux" => { "enabled" => true, "enforcement" => mode, "policy_identity" => identity,
          "policy" => { "port_inventory" => { "status" => "observed", "mappings" => [] } },
          "booleans" => [{ "name" => "httpd_read_user_content", "current" => false, "status" => "observed" }] } } }
    post "/api/v1/heartbeat", params: payload.to_json, headers: headers
    expect(response).to have_http_status(:accepted)
  end

  def status(offset, sequence, old_mode, new_mode, result: "res=1", enabled: "1", boot: "boot-1")
    fields = "enforcing=#{new_mode == 'enforcing' ? 1 : 0} old_enforcing=#{old_mode == 'enforcing' ? 1 : 0} auid=0 ses=570 enabled=#{enabled} old-enabled=1 lsm=selinux #{result}"
    records = [[1404, "MAC_STATUS", fields], [1300, "SYSCALL", 'syscall=1 success=yes exit=1 comm="setenforce" exe="/usr/sbin/setenforce"'],
      [1327, "PROCTITLE", "proctitle=736574656E666F7263650030"], [1320, "EOE", ""]]
    post "/api/v1/events", params: request_for(offset, sequence, boot, records, "selinux_administrative").to_json, headers: headers
    expect(response).to have_http_status(:accepted)
    RawEvent.find_by!(boot_id: boot, audit_sequence: sequence)
  end

  def avc(offset, sequence, permissive, checkpoint_at:, invalidated: [], boot: "boot-1")
    request = request_for(offset, sequence, boot, [[1400, "AVC", avc_text(permissive)]], "avc", checkpoint_at)
    request["checkpoint_invalidated_fields"] = invalidated
    post "/api/v1/events", params: request.to_json, headers: headers
    expect(response).to have_http_status(:accepted)
    RawEvent.find_by!(boot_id: boot, audit_sequence: sequence).occurrences.sole
  end

  def avc_text(permissive)
    "avc: denied { read } for comm=\"httpd\" name=\"harmless\" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=#{permissive}"
  end

  def request_for(offset, sequence, boot, records, category, observed = nil)
    time = (base + offset).iso8601(6)
    { "schema_version" => 4, "agent" => { "version" => "test" }, "host_id" => "mode-host", "boot_id" => boot,
      "host_observed_at" => observed.nil? ? nil : (base + observed).iso8601(6), "events" => [{ "category" => category,
        "audit_event" => { "timestamp" => time, "sequence" => sequence }, "agent_received_at" => time, "completion_reason" => "eoe",
        "records" => records.each_with_index.map { |(code, name, fields), position| { "position" => position, "type" => code, "type_name" => name,
          "timestamp" => time, "sequence" => sequence, "payload" => Base64.strict_encode64("audit(#{(base + offset).to_f}:#{sequence}): #{fields}") } } }] }
  end
end
