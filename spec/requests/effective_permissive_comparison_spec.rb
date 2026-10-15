require "rails_helper"

RSpec.describe "Effective permissive-domain reference comparison", type: :request do
  include ActiveJob::TestHelper
  before { sign_in_operator }
  after do
    CatalogPolicyArtifact.delete_all
    DistributionCatalogImport.delete_all
    DistributionCatalogBoolean.delete_all
    DistributionCatalogPort.delete_all
    DistributionCatalogRevision.delete_all
    PolicyArtifact.delete_all
    RawAuditRecord.delete_all
    RawEvent.delete_all
    HostSnapshotObservation.delete_all
    HostSnapshot.delete_all
    AgentInstallation.delete_all
    Host.delete_all
    Organization.delete_all
    clear_enqueued_jobs
  end

  def policy(bytes, domains: [], status: "observed", semantics: 1, evaluator: "SETools test")
    artifact = PolicyArtifact.store!(policy_identity: "sha256:#{Digest::SHA256.hexdigest(bytes)}", bytes: bytes, defer_analysis: true)
    artifact.update_column(:permissive_domain_analysis, { "status" => status, "domains" => domains,
      "policy_identity" => artifact.policy_identity, "semantics_version" => semantics, "evaluator_version" => evaluator,
      "error_message" => "PRIVATE parser stderr /secret/path", "evaluated_at" => Time.current.iso8601,
      "last_enqueued_at" => Time.current.iso8601 })
    artifact
  end

  def catalog(artifact, companion: false, type: "targeted", description: nil)
    document = JSON.parse(File.binread(Rails.root.join("spec/fixtures/catalogs/v4.json")))
    document["catalog"]["platform"]["distribution"] = "almalinux"
    document["catalog"]["policy"]["type"] = type
    document["catalog"]["policy"]["loaded_policy_digest"] = artifact.policy_identity
    document["catalog"]["families"]["effective_permissive_domains"]["domains"] = artifact.permissive_domain_analysis.fetch("domains")
    document["catalog"]["families"]["effective_permissive_domains"]["evaluator_version"] = artifact.permissive_domain_analysis.fetch("evaluator_version")
    document["catalog"]["families"]["booleans"]["entries"].first["description"] = description if description
    document["content_digest"] = "sha256:#{Digest::SHA256.hexdigest(DistributionCatalogCanonicalizer.call(document['catalog']))}"
    record = ImportDistributionCatalog.call(artifact: DistributionCatalogArtifact.new(JSON.generate(document))).revision
    AttachCatalogPolicy.call(revision: record, bytes: artifact.artifact, acquisition_basis: "Synthetic comparison fixture") if companion
    record
  end

  def host(artifact, stale: false, platform: { "os_id" => "almalinux", "os_version" => "9.8", "architecture" => "amd64" })
    org = Organization.create!(name: SecureRandom.uuid)
    record = org.hosts.create!(external_id: SecureRandom.uuid, hostname: "fixture-host")
    snapshot = record.host_snapshots.create!(details: { "boot_id" => "fixture-boot", "platform" => platform,
      "selinux" => { "policy_identity" => artifact.policy_identity, "configured_policy_type" => "targeted", "boolean_status" => "observed", "booleans" => [], "policy" => { "port_inventory" => { "status" => "observed", "mappings" => [] } } } })
    agent = org.agent_installations.create!(name: "fixture-agent", bound_host: record)
    time = stale ? 1.hour.ago : Time.current
    record.host_snapshot_observations.create!(host_snapshot: snapshot, agent_installation: agent, first_observed_at: time, last_observed_at: time, first_received_at: time, last_received_at: time)
    record
  end

  def compare(record, revision = nil)
    get "/api/v1/hosts/#{record.id}/configuration", params: revision ? { reference_revision_id: revision.id } : {}
    expect(response).to have_http_status(:ok)
    expect(response.body).not_to include("PRIVATE", "/secret/path")
    response.parsed_body.fetch("comparison").fetch("effective_permissive_domains")
  end

  it "compares exact automatic authority without executing a parser and exposes reproducible identities" do
    artifact = policy("exact", domains: %w[bootupd_t rhcd_t])
    revision = catalog(artifact)
    record = host(artifact)
    expect(PolicyPermissiveDomainAnalyzer).not_to receive(:call)
    result = compare(record)
    expect(result).to include("status" => "observed", "reason" => nil, "matching" => %w[bootupd_t rhcd_t], "unexpected_on_host" => [], "missing_from_host" => [])
    expect(result["counts"]).to eq("matching" => 2, "unexpected_on_host" => 0, "missing_from_host" => 0)
    expect(result["host"]).to include("policy_identity" => artifact.policy_identity, "snapshot_id" => record.current_snapshot.id, "semantics_version" => 1)
    expect(result["reference"]).to include("revision_id" => revision.id, "content_digest" => revision.content_digest, "policy_identity" => artifact.policy_identity, "provenance" => "inline_catalog_extraction", "semantics_version" => 1, "evaluator_version" => "SETools test")
    expect(revision.catalog_policy_artifact).to be_nil
    expect(result["selection"]).to include("basis" => "exact_policy_identity", "equivalence_asserted" => true)
    expect(response.parsed_body.dig("selection", "families", "effective_permissive_domains")).to include("status" => "comparable", "comparison_allowed" => true)
  end

  [[[], [], [], [], []], [%w[postgres_t], [], [], %w[postgres_t], []], [%w[alpha_t postgres_t], %w[alpha_t], %w[alpha_t], %w[postgres_t], []],
   [[], %w[postgres_t], [], [], %w[postgres_t]], [%w[z_t alpha_t], %w[b_t alpha_t], %w[alpha_t], %w[z_t], %w[b_t]]].each do |h, r, matching, unexpected, missing|
    it "computes complete explicit set algebra for host=#{h.inspect} reference=#{r.inspect}" do
      host_artifact = policy("host", domains: h.sort)
      reference_artifact = policy("reference", domains: r.sort, evaluator: "SETools compatible newer")
      revision = catalog(reference_artifact)
      result = compare(host(host_artifact), revision)
      expect(result).to include("status" => "observed", "matching" => matching, "unexpected_on_host" => unexpected, "missing_from_host" => missing)
      expect(result["selection"]).to include("mode" => "explicit", "policy_identity_match" => false, "equivalence_asserted" => false)
    end
  end

  %w[pending unavailable error].each do |status|
    it "withholds sets when host analysis is #{status}" do
      ref = catalog(policy("reference"))
      result = compare(host(policy("host", status: status)), ref)
      expect(result).to include("status" => "unknown", "reason" => "host_permissive_analysis_#{status}", "matching" => nil, "counts" => nil)
    end
    it "uses inline facts even when a separately stored reference artifact analysis is #{status}" do
      ref = catalog(policy("reference", status: status))
      result = compare(host(policy("host")), ref)
      expect(result).to include("status" => "observed", "reason" => nil, "matching" => [])
    end
  end

  it "compares inline permissive membership on automatic major-release family agreement when the candidate set is unanimous" do
    ref = catalog(policy("reference", domains: %w[postgres_t]))
    result = compare(host(policy("host", domains: %w[postgres_t])))
    expect(result).to include("status" => "observed", "reason" => nil, "matching" => ["postgres_t"], "unexpected_on_host" => [], "missing_from_host" => [])
    expect(response.parsed_body.dig("selection", "basis")).to eq("major_release_family_agreement")
    expect(result.dig("selection", "equivalence_asserted")).to be(false)
    expect(ref.reference_permissive_domains[:status]).to eq("observed")
  end

  it "withholds only effective permissive comparison when major-release candidates disagree on inline membership" do
    catalog(policy("reference one", domains: ["alpha_t"]))
    catalog(policy("reference two", domains: ["beta_t"]))
    result = compare(host(policy("host", domains: ["alpha_t"])))

    expect(response.parsed_body.dig("selection", "basis")).to eq("major_release_family_agreement")
    expect(response.parsed_body.dig("selection", "families", "booleans")).to include("comparison_allowed" => true)
    expect(result).to include("status" => "unknown", "reason" => "effective_permissive_reference_ambiguous", "matching" => nil)
  end

  it "withholds effective membership when an eligible legacy candidate has no inline facts" do
    complete = catalog(policy("v4 candidate", domains: ["postgres_t"]))
    legacy = DistributionCatalogRevision.create!(schema_version: 1, collector_semantics_version: 3,
      content_digest: "sha256:" + "b" * 64, loaded_policy_digest: "sha256:" + "c" * 64,
      policy_type: "targeted", kernel_policy_version: 33, distribution: "almalinux", major_version: "9",
      architecture: "x86_64", policy_packages: [], booleans_complete: true, ports_complete: true)
    complete.distribution_catalog_booleans.each do |entry|
      legacy.distribution_catalog_booleans.create!(name: entry.name, default_value: entry.default_value, description: entry.description)
    end
    complete.distribution_catalog_ports.each do |mapping|
      legacy.distribution_catalog_ports.create!(protocol: mapping.protocol, start_port: mapping.start_port, end_port: mapping.end_port, selinux_type: mapping.selinux_type)
    end

    result = compare(host(policy("host", domains: ["postgres_t"])))

    expect(response.parsed_body.dig("selection", "basis")).to eq("major_release_family_agreement")
    expect(response.parsed_body.dig("selection", "families", "effective_permissive_domains")).to include(
      "status" => "unknown", "comparison_allowed" => false, "reason" => "reference_inline_facts_unavailable")
    expect(result).to include("status" => "unknown", "reason" => "reference_inline_facts_unavailable", "matching" => nil)
  end

  it "distinguishes absent, ambiguous, archived and incompatible reference selection" do
    record = host(policy("host"))
    expect(compare(record)["reason"]).to eq("reference_absent")
    first = catalog(policy("one"))
    catalog(policy("two"), description: "different family")
    expect(compare(record)["reason"]).to eq("reference_ambiguous")
    first.catalog_management.change!(lifecycle: "archived", changed_by: "test")
    expect(compare(record, first)["reason"]).to eq("reference_archived")
    incompatible = catalog(policy("mls"), type: "mls")
    expect(compare(record, incompatible)["reason"]).to eq("incompatible_policy_context")
  end

  it "reports unavailable reference selection when automatic platform context is missing" do
    expect(compare(host(policy("host"), platform: {}))["reason"]).to eq("reference_unavailable")
  end

  it "uses inline reference facts independently of missing or corrupt companions, but still requires host artifacts" do
    artifact = policy("reference")
    revision = catalog(artifact, companion: false)
    record = host(policy("host"))
    expect(compare(record, revision)["status"]).to eq("observed")
    AttachCatalogPolicy.call(revision: revision, bytes: artifact.artifact, acquisition_basis: "Synthetic")
    PolicyArtifact.where(id: artifact.id).update_all(artifact: "corrupt")
    expect(compare(record, revision)["status"]).to eq("observed")
    reference_two = catalog(policy("valid reference"))
    PolicyArtifact.where(policy_identity: record.current_policy_identity).delete_all
    expect(compare(record, reference_two)["reason"]).to eq("host_policy_artifact_unavailable")
  end

  it "compares JSON-only reference facts after reference policy bytes are absent" do
    reference_artifact = policy("reference only", domains: ["reference_t"])
    revision = catalog(reference_artifact)
    reference_artifact.delete
    record = host(policy("host only", domains: ["host_t"]))
    expect(PolicyPermissiveDomainAnalyzer).not_to receive(:call)
    expect do
      result = compare(record, revision)
      expect(result).to include("status" => "observed", "unexpected_on_host" => ["host_t"], "missing_from_host" => ["reference_t"])
    end.not_to have_enqueued_job(AnalyzePolicyPermissiveDomainsJob)
  end

  it "keeps incompatible host cache semantics unknown" do
    revision = catalog(policy("reference"))
    result = compare(host(policy("host", semantics: 2)), revision)
    expect(result).to include("status" => "unknown", "reason" => "host_permissive_analysis_unavailable", "counts" => nil)
  end

  it "does not borrow old membership for masked or stale checkpoints" do
    artifact = policy("exact", domains: %w[postgres_t])
    revision = catalog(artifact)
    record = host(artifact, stale: true)
    expect(compare(record)["reason"]).to eq("stale_host_observation")
    snapshot = record.current_snapshot
    agent = record.agent_installations.first
    record.raw_events.create!(organization: record.organization, agent_installation: agent, category: "selinux_administrative", schema_version: 4,
      boot_id: "fixture-boot", audit_timestamp: Time.current, audit_sequence: 1, completion_reason: "eoe", agent_received_at: Time.current,
      server_received_at: Time.current, evidence_digest: "fixture", transition_type: "policy_load", host_snapshot: snapshot)
    expect(compare(record, revision)).to include("status" => "unknown", "reason" => "host_policy_identity_unavailable", "matching" => nil)
  end

  it "refuses incompatible inline extraction semantics without requiring identical tool versions" do
    revision = catalog(policy("reference"))
    revision.update_column(:effective_permissive_domains, revision.effective_permissive_domains.merge("extractor_semantics_version" => 2))
    result = compare(host(policy("host")), revision)
    expect(result).to include("status" => "unknown", "reason" => "reference_extraction_semantics_incompatible")
  end
end
