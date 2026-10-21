require "rails_helper"
require_relative "../support/port_resolution_fixtures"

RSpec.describe "Reviewed port mapping workflow", type: :request do
  include PortResolutionFixtures
  around do |example|
    ActiveRecord::Base.transaction do
      example.run
      raise ActiveRecord::Rollback
    end
  end
  before { sign_in_operator }

  def workflow(issue)
    get "/api/v1/issues/#{issue.id}/resolutions"
    expect(response).to have_http_status(:ok)
    JSON.parse(response.body)
  end

  def choose(issue, candidate)
    patch "/api/v1/issues/#{issue.id}/resolution-intent", params: {
      candidate_id: candidate["id"], evidence_version: candidate["evidence_version"] }.to_json,
      headers: { "Content-Type" => "application/json", "X-CSRF-Token" => response.headers["X-CSRF-Token"] }
  end

  it "distinguishes a historical SSH classification from latest generic inventory and plans against the latter" do
    issue, occurrence, host, snapshot, fact = port_fixture(port: 23451)
    issue.update!(target_type: "ssh_port_t")
    occurrence.normalized_denial.update!(target_type: "ssh_port_t")
    historical_identity = occurrence.policy_identity
    current_identity = "sha256:#{SecureRandom.hex(32)}"
    replace_port_snapshot(host, snapshot, "selinux" => { "policy_identity" => current_identity })
    fact.update!(policy_identity: current_identity)

    body = workflow(issue)
    comparison = body.fetch("port_investigations").sole
    expect(comparison).to include("occurrence_id" => occurrence.id, "occurred_at" => occurrence.occurred_at.iso8601(3),
      "historical_policy_identity" => historical_identity, "current_policy_identity" => current_identity,
      "classification_differs" => true, "policy_differs" => true, "observed_type" => "ssh_port_t")
    expect(comparison.fetch("current_mappings").sole).to include("type" => "unreserved_port_t")
    get "/api/v1/issues/#{issue.id}"
    expect(JSON.parse(response.body).dig("resolutions", "port_investigations").sole).to eq(comparison)
    expect(ResolutionIntentChange.where(issue: issue)).to be_empty

    choose(issue, body.fetch("candidates").sole)
    expect(response).to have_http_status(:ok)
    plan = workflow(issue).fetch("change_plan")
    expect(plan.fetch("apply_steps").sole["command"]).to eq("sudo semanage port -a -p tcp -t http_port_t 23451")
    expect(plan.fetch("rollback_steps").sole["command"]).to eq("sudo semanage port -d -p tcp 23451")
    expect(occurrence.normalized_denial.reload.target_type).to eq("ssh_port_t")
  end

  it "requires reviewed intent for concrete add/verify/rollback commands and preserves equivalent growth" do
    issue, occurrence, host, snapshot, = port_fixture
    body = workflow(issue)
    candidate = body["candidates"].sole
    expect(body.to_json).not_to include("sudo semanage port")
    expect(candidate).to include("kind" => "set_port_mapping", "scope_kind" => "host_port")
    expect(candidate.dig("evidence_basis", "prior_mappings").sole).to include("type" => "unreserved_port_t", "start" => 1024, "end" => 32767)
    choose(issue, candidate)
    expect(response).to have_http_status(:ok)
    reviewed = workflow(issue)
    plan = reviewed["change_plan"]
    expect(plan["apply_steps"].sole).to include("command" => "sudo semanage port -a -p tcp -t http_port_t 12345", "persistence" => "port_mapping")
    expect(plan["verification_steps"].sole["explanation"]).to include("listener", "application request", "silence alone is not success")
    expect(plan["rollback_steps"].sole["command"]).to eq("sudo semanage port -d -p tcp 12345")
    repeated = occurrence.dup
    denial = occurrence.normalized_denial.dup
    denial.ordinal = 1
    denial.save!
    repeated.normalized_denial = denial
    repeated.occurred_at += 1.second
    repeated.save!
    replace_port_snapshot(host, snapshot, "selinux" => { "booleans" => [{ "name" => "unrelated", "status" => "observed", "current" => false }] })
    expect(workflow(issue)).to include("freshness" => "current", "change_plan" => plan)
    expect(ResolutionIntentChange.where(issue: issue).count).to eq(1)
  end

  it "withholds and rejects stale reviewed commands when prior state or boot changes" do
    issue, _, host, snapshot, = port_fixture
    candidate = workflow(issue)["candidates"].sole
    choose(issue, candidate)
    replace_port_snapshot(host, snapshot, "boot_id" => "new-boot")
    body = workflow(issue)
    expect(body).to include("freshness" => "evidence_changed", "change_plan" => nil)
    choose(issue, candidate)
    expect(response).to have_http_status(:conflict)
    updated = body["candidates"].sole
    choose(issue, updated)
    expect(response).to have_http_status(:ok)
    latest = host.reload.current_snapshot
    replace_port_snapshot(host, latest, "selinux" => { "policy" => { "port_inventory" => { "mappings" => [port_range("ssh_port_t", 12345)] } } })
    expect(workflow(issue)).to include("freshness" => "no_longer_supported", "change_plan" => nil)
    expect(ResolutionIntentChange.where(issue: issue).count).to eq(2)
  end

  it "uses candidate-specific mapping semantics and retains unrelated host/port independence" do
    issue, _, host, snapshot, = port_fixture
    _, other, other_host, other_snapshot, = port_fixture(issue: issue, port: 23456)
    selected = workflow(issue)["candidates"].find { |item| item["host_id"] == host.id }
    choose(issue, selected)
    mappings = snapshot.details.dig("selinux", "policy", "port_inventory", "mappings") + [port_range("ssh_port_t", 40000)]
    replace_port_snapshot(host, snapshot, "selinux" => { "policy" => { "port_inventory" => { "mappings" => mappings } } })
    replace_port_snapshot(other_host, other_snapshot, "selinux" => { "policy" => { "port_inventory" => { "status" => "partial" } } })
    expect(workflow(issue)["freshness"]).to eq("current")
    get "/api/v1/issues/#{issue.id}"
    expect(response).to have_http_status(:ok)
    body = JSON.parse(response.body)
    expect(body.dig("resolutions", "port_investigations").map { |item| item["port"] }).to contain_exactly(12345, 23456)
    expect(body.dig("resolutions", "port_investigations").find { |item| item["occurrence_id"] == other.id }["reason"]).to include("partial")
  end

  it "withholds plans for stale, masked and missing configuration rather than borrowing historical evidence" do
    issue, _, host, snapshot, = port_fixture
    choose(issue, workflow(issue)["candidates"].sole)
    host.host_snapshot_observations.first.update!(last_received_at: 1.hour.ago)
    expect(workflow(issue)).to include("freshness" => "evidence_changed", "change_plan" => nil)
    host.host_snapshot_observations.first.update!(last_received_at: Time.current)
    replace_port_snapshot(host, snapshot, "selinux" => { "policy_identity" => nil })
    body = workflow(issue)
    expect(body["change_plan"]).to be_nil
    expect(body["port_investigations"].sole["reason"]).to include("identity is missing or invalidated")
  end

  it "requires review after the relevant applicable rule, Boolean state or exact identity changes" do
    issue, _, host, snapshot, fact = port_fixture
    choose(issue, workflow(issue)["candidates"].sole)
    fact.update!(evaluator_version: "new evaluator")
    expect(workflow(issue)["freshness"]).to eq("evidence_changed")
    choose(issue, workflow(issue)["candidates"].sole)
    fact.update!(status: "no_match", matching_rules: [], rule_details: [])
    expect(workflow(issue)).to include("freshness" => "no_longer_supported", "change_plan" => nil)
    replace_port_snapshot(host, snapshot, "selinux" => { "policy_identity" => "sha256:#{SecureRandom.hex(32)}" })
    expect(workflow(issue)["port_investigations"].sole["state"]).to eq("pending")
  end

  it "registers one asynchronous port-discovery question per exact source/class/operation identity" do
    issue, = port_fixture
    PolicyFact.where(query_kind: PolicyFact::PORT_QUERY_KIND).delete_all
    2.times { RequestResolutionPolicyFactsJob.perform_now(issue_id: issue.id) }
    fact = PolicyFact.where(query_kind: PolicyFact::PORT_QUERY_KIND).sole
    expect(fact).to have_attributes(source_type: "httpd_t", target_type: "port_type", object_class: "tcp_socket", permission: "name_bind", status: "pending")
    expect(workflow(issue)["port_investigations"].sole["state"]).to eq("pending")
  end

  it "uses actual occurrence operations without changing legacy grouped issue identity" do
    issue, occurrence, = port_fixture
    issue.update!(fingerprint_version: 2, permissions: [])
    digest = issue.fingerprint_digest
    PolicyFact.where(query_kind: PolicyFact::PORT_QUERY_KIND).delete_all
    RequestResolutionPolicyFactsJob.perform_now(issue_id: issue.id)
    expect(PolicyFact.where(query_kind: PolicyFact::PORT_QUERY_KIND).sole.permission).to eq("name_bind")
    expect(workflow(issue)["port_investigations"].sole).to include("operation" => "name_bind", "occurrence_id" => occurrence.id)
    expect(issue.reload.fingerprint_digest).to eq(digest)
  end

  it "withholds a conditional mapping when a relevant Boolean becomes inactive" do
    issue, _, host, snapshot, fact = port_fixture
    rule = "allow httpd_t http_port_t:tcp_socket name_bind; [ feature_enabled ]:True"
    fact.update!(matching_rules: [rule], rule_details: [{ "rule" => rule, "target_types" => ["http_port_t"], "conditional_expression" => "feature_enabled" }, fact.rule_details.last])
    current = replace_port_snapshot(host, snapshot, "selinux" => { "booleans" => [{ "name" => "feature_enabled", "status" => "observed", "current" => true }] })
    choose(issue, workflow(issue)["candidates"].sole)
    replace_port_snapshot(host, current, "selinux" => { "booleans" => [{ "name" => "feature_enabled", "status" => "observed", "current" => false }] })
    body = workflow(issue)
    expect(body).to include("freshness" => "no_longer_supported", "change_plan" => nil)
    expect(body["port_investigations"].sole["types"].sole["state"]).to eq("conditional")
  end

  it "requires review for changed prior-state mechanics and the port-specific generation version" do
    issue, _, host, snapshot, fact = port_fixture
    choose(issue, workflow(issue)["candidates"].sole)
    replace_port_snapshot(host, snapshot, "selinux" => { "policy" => { "port_inventory" => {
      "mappings" => [port_range("unreserved_port_t", 12345, provenance: "custom")] } } })
    fact.update!(rule_details: [fact.rule_details.first, { "kind" => "port_contexts", "protocol" => "tcp",
      "mappings" => [{ "type" => "unreserved_port_t", "start" => 12345, "end" => 12345 }] }])
    body = workflow(issue)
    expect(body).to include("freshness" => "evidence_changed", "change_plan" => nil)
    expect(body["candidates"].sole.dig("evidence_basis", "action")).to eq("modify")
    choose(issue, body["candidates"].sole)
    stub_const("PortMappingGuidance::PLAN_SEMANTICS_VERSION", 2)
    expect(workflow(issue)).to include("freshness" => "evidence_changed", "change_plan" => nil)
  end

  it "returns complete sourced type choices without making description metadata part of reviewed mechanics" do
    issue, = port_fixture
    before = workflow(issue)
    expect(before["port_investigations"].sole["types"].sole.dig("service", "id")).to eq("http")
    candidate = before["candidates"].sole
    choose(issue, candidate)
    reviewed = workflow(issue)["change_plan"]
    reference = PortServiceDescriptions.for("http_port_t")
    allow(PortServiceDescriptions).to receive(:for).with("http_port_t").and_return(reference.merge(label: "Updated reference wording"))
    after = workflow(issue)
    expect(after["port_investigations"].sole["types"].sole.dig("service", "label")).to eq("Updated reference wording")
    expect(after["candidates"].sole["evidence_version"]).to eq(candidate["evidence_version"])
    expect(after).to include("freshness" => "current", "change_plan" => reviewed)
  end

  it "makes all discovered types and their reviewable candidates available through the API" do
    issue, _, _, _, fact = port_fixture
    types = 18.times.map { |index| "service_#{index}_port_t" } + ["http_port_t"]
    rule = "allow httpd_t test_ports:tcp_socket name_bind;"
    fact.update!(matching_rules: [rule], rule_details: [{ "rule" => rule, "target_types" => types }, fact.rule_details.last])
    body = workflow(issue)
    expect(body["port_investigations"].sole["types"].map { |option| option["type"] }).to match_array(types)
    expect(body["candidates"].map { |candidate| candidate.dig("evidence_basis", "target_port_type") }).to match_array(types)
    expect(body.to_json).not_to include("sudo semanage port")
  end
end
