require "rails_helper"

RSpec.describe PolicyPermissiveDomains do
  include ActiveJob::TestHelper

  after do
    Occurrence.delete_all
    NormalizedDenial.delete_all
    RawAuditRecord.delete_all
    RawEvent.delete_all
    HostSnapshotObservation.delete_all
    HostSnapshot.delete_all
    AgentInstallation.delete_all
    Issue.delete_all
    PolicyFact.delete_all
    PolicyArtifact.delete_all
    Host.delete_all
    Organization.delete_all
    clear_enqueued_jobs
  end

  def artifact(domains: nil, status: nil, bytes: "test policy")
    result = status ? { "status" => status, "domains" => domains, "evaluator_version" => "test",
      "semantics_version" => PolicyPermissiveDomainAnalyzer::SEMANTICS_VERSION,
      "policy_identity" => "sha256:#{Digest::SHA256.hexdigest(bytes)}" } : {}
    PolicyArtifact.create!(policy_identity: "sha256:#{Digest::SHA256.hexdigest(bytes)}", artifact: bytes, artifact_size: bytes.bytesize, permissive_domain_analysis: result)
  end

  def occurrence(policy, local: true, mode: "enforcing", source: "postgresql_t", mask: [])
    organization = Organization.first || Organization.create!(name: "exact-permissive")
    host = organization.hosts.create!(external_id: "host-#{Host.count}")
    snapshot = host.host_snapshots.create!(details: { "boot_id" => "boot", "selinux" => { "policy_identity" => policy.policy_identity, "enforcement" => mode } })
    installation = host.agent_installations.create!(organization: organization, name: host.external_id)
    raw = host.raw_events.create!(organization: organization, agent_installation: installation, host_snapshot: snapshot, schema_version: 4, category: "avc", boot_id: "boot", audit_timestamp: Time.current, audit_sequence: 1, agent_received_at: Time.current, server_received_at: Time.current, completion_reason: "eoe", evidence_digest: "digest", checkpoint_invalidated_fields: mask)
    denial = raw.normalized_denials.create!(status: "ok", normalization_version: 1, ordinal: 0, source_type: source, details: { "permissive" => local, "enforcement_mode" => local ? "permissive" : "enforcing" })
    host.occurrences.create!(organization: organization, raw_event: raw, normalized_denial: denial, host_snapshot: snapshot, occurred_at: raw.audit_timestamp)
  end

  [[], ["postgresql_t"], %w[postgresql_t rhcd_t]].each do |domains|
    it "reuses the observed #{domains.inspect} set by exact SHA, including authoritative empty" do
      policy = artifact(domains: domains, status: "observed")
      expect(PolicyPermissiveDomainAnalyzer).not_to receive(:call)
      2.times { expect(described_class.lookup(policy.policy_identity)).to include(status: "observed", domains: domains, provenance: "exact_loaded_policy_artifact") }
      expect(PolicyArtifact.count).to eq(1)
    end
  end

  it "enqueues legacy/new artifacts once and serializes concurrent analysis, then reuses results" do
    policy = artifact
    allow(PolicyPermissiveDomainAnalyzer).to receive(:call).and_return({ "status" => "observed", "domains" => ["postgresql_t"], "evaluator_version" => "test" })
    expect { 2.times { described_class.lookup(policy.policy_identity) } }.not_to have_enqueued_job(AnalyzePolicyPermissiveDomainsJob)
    2.times.map { Thread.new { AnalyzePolicyPermissiveDomainsJob.perform_now(policy.id) } }.each(&:value)
    expect(PolicyPermissiveDomainAnalyzer).to have_received(:call).once
    expect(described_class.lookup(policy.policy_identity)[:domains]).to eq(["postgresql_t"])
  end

  it "keeps missing identity/artifact and failed analysis unknown, never empty" do
    expect(described_class.lookup(nil)).to include(status: "unavailable", domains: nil, policy_identity: nil)
    expect(described_class.lookup("sha256:" + "a" * 64)).to include(status: "unavailable", domains: nil)
    %w[unavailable error pending].each do |status|
      policy = artifact(domains: ["stale_t"], status: status, bytes: status)
      expect(described_class.lookup(policy.policy_identity)).to include(status: status, domains: nil)
    end
  end

  it "preserves AVC-local permissiveness separately from global Enforcing and historical membership" do
    permissive = artifact(domains: ["postgresql_t"], status: "observed")
    ordinary = artifact(domains: [], status: "observed", bytes: "ordinary policy")
    old = occurrence(permissive)
    later = occurrence(ordinary, local: false)
    facts = described_class.for_identities([permissive.policy_identity, ordinary.policy_identity])
    expect(described_class.for_occurrence(old, facts)).to include(source_domain_permissive: true, avc_policy_consistency: "consistent", policy_identity: permissive.policy_identity)
    expect(old.raw_event.checkpoint_enforcement_mode(old.host_snapshot)).to eq("enforcing")
    expect(described_class.for_occurrence(later, facts)).to include(source_domain_permissive: false)
    expect(described_class.for_occurrence(old, facts)[:source_domain_permissive]).to eq(true)
  end

  it "never recovers masked identity from a known old artifact, while other scoped masks retain membership" do
    policy = artifact(domains: ["postgresql_t"], status: "observed")
    masked = occurrence(policy, mask: ["policy_identity"])
    expect(described_class.for_occurrence(masked)).to include(status: "unavailable", policy_identity: nil, source_domain_permissive: nil)
    scoped = occurrence(policy, mask: ["enforcement"])
    expect(described_class.for_occurrence(scoped)).to include(status: "observed", source_domain_permissive: true)
    host = scoped.host
    host.host_snapshot_observations.create!(host_snapshot: scoped.host_snapshot, agent_installation: scoped.raw_event.agent_installation, first_observed_at: 1.minute.ago, last_observed_at: 1.minute.ago, first_received_at: Time.current, last_received_at: Time.current)
    host.raw_events.create!(masked.raw_event.attributes.except("id", "host_id", "agent_installation_id", "host_snapshot_id").merge("host_id" => host.id, "agent_installation_id" => scoped.raw_event.agent_installation_id, "audit_sequence" => 2))
    expect(HostSerializer.call(host, include_snapshot: true).dig(:selinux, :effective_permissive_domains)).to include(status: "unavailable", domains: nil)
  end

  it "treats meaningful mismatch as diagnostic and allows global permissiveness to explain ordinary membership" do
    policy = artifact(domains: [], status: "observed")
    expect(described_class.for_occurrence(occurrence(policy))).to include(avc_policy_consistency: "diagnostic_mismatch")
    expect(described_class.for_occurrence(occurrence(policy, mode: "permissive"))).to include(avc_policy_consistency: "global_mode_may_explain")
    expect(Issue.count).to eq(0)
  end

  it "derives deterministic added/removed and equal-policy comparisons without creating event evidence" do
    before = artifact(domains: %w[legacy_t rhcd_t], status: "observed")
    after = artifact(domains: %w[postgresql_t rhcd_t], status: "observed", bytes: "new policy")
    expect(described_class.compare(before.policy_identity, after.policy_identity)).to include(added: ["postgresql_t"], removed: ["legacy_t"], evidence_class: "derived_exact_policy_comparison")
    expect(described_class.compare(before.policy_identity, before.policy_identity)).to include(added: [], removed: [])
    expect(described_class.compare(before.policy_identity, "sha256:" + "b" * 64)).to be_nil
    expect(RawEvent.count).to eq(0)
  end

  it "projects 1000 occurrences from one cached query without subprocesses or N+1 fact reads" do
    policy = artifact(domains: ["postgresql_t"], status: "observed")
    item = occurrence(policy)
    expect(PolicyPermissiveDomainAnalyzer).not_to receive(:call)
    reads = []
    subscriber = ActiveSupport::Notifications.subscribe("sql.active_record") { |*args| sql = args.last[:sql]; reads << sql if sql.include?("policy_artifacts") }
    facts = OccurrenceDetailSerializer.policy_states(Array.new(1000, item))
    1000.times { expect(described_class.for_occurrence(item, facts)[:source_domain_permissive]).to eq(true) }
    expect(reads.size).to eq(1)
    expect(reads.first).not_to match(/"policy_artifacts"\."artifact"/)
  ensure
    ActiveSupport::Notifications.unsubscribe(subscriber) if subscriber
  end
end

RSpec.describe PolicyPermissiveDomainAnalyzer do
  def policy(bytes = "binary policy")
    PolicyArtifact.new(policy_identity: "sha256:#{Digest::SHA256.hexdigest(bytes)}", artifact: bytes)
  end

  it "uses authoritative SETools output, validates identifiers and canonicalizes domains" do
    status = instance_double(Process::Status, success?: true)
    allow(SetoolsProcess).to receive(:call).and_return([JSON.generate(domains: %w[rhcd_t postgresql_t rhcd_t], evaluator_version: "SETools test"), "", status])
    expect(described_class.call(policy)).to include("status" => "observed", "domains" => %w[postgresql_t rhcd_t])
    expect(SetoolsProcess).to have_received(:call).with("python3", Rails.root.join("script/policy_permissive_domains.py").to_s, anything)
    allow(SetoolsProcess).to receive(:call).and_return([JSON.generate(domains: ["invalid type"], evaluator_version: "test"), "", status])
    expect(described_class.call(policy)).to include("status" => "error")
  end

  it "distinguishes authoritative empty, unavailable parser and invalid artifact" do
    status = instance_double(Process::Status, success?: true)
    allow(SetoolsProcess).to receive(:call).and_return([JSON.generate(domains: [], evaluator_version: "test"), "", status])
    expect(described_class.call(policy)).to include("status" => "observed", "domains" => [])
    allow(SetoolsProcess).to receive(:call).and_raise(Errno::ENOENT)
    expect(described_class.call(policy)["status"]).to eq("unavailable")
    allow(SetoolsProcess).to receive(:call).and_return(["", "invalid binary policy", instance_double(Process::Status, success?: false, exitstatus: 1)])
    expect(described_class.call(policy)["status"]).to eq("error")
    artifact = policy
    artifact.policy_identity = "sha256:" + "a" * 64
    expect(described_class.call(artifact)["status"]).to eq("unavailable")
  end

  it "rejects malformed/duplicate-key JSON, invalid versions and oversized output without facts" do
    success = instance_double(Process::Status, success?: true)
    ["progress {}", '{"domains":[],"domains":[],"evaluator_version":"test"}', JSON.generate(domains: [], evaluator_version: 1), "x" * (SetoolsProcess::MAX_OUTPUT + 1)].each do |output|
      allow(SetoolsProcess).to receive(:call).and_return([output, "", success])
      expect(described_class.call(policy)).to include("status" => "error")
      expect(described_class.call(policy)).not_to have_key("domains")
    end
  end
end
