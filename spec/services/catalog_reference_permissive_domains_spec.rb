require "rails_helper"

RSpec.describe "Inline catalog reference permissive domains" do
  include ActiveJob::TestHelper

  def revision(bytes = "reference policy", domains: ["example_t"])
    document = JSON.parse(File.binread(Rails.root.join("spec/fixtures/catalogs/v4.json")))
    document["catalog"]["platform"]["distribution"] = "almalinux"
    document["catalog"]["policy"]["loaded_policy_digest"] = "sha256:#{Digest::SHA256.hexdigest(bytes)}"
    document["catalog"]["families"]["effective_permissive_domains"]["domains"] = domains
    document["content_digest"] = "sha256:#{Digest::SHA256.hexdigest(DistributionCatalogCanonicalizer.call(document['catalog']))}"
    ImportDistributionCatalog.call(artifact: DistributionCatalogArtifact.new(JSON.generate(document))).revision
  end

  def comparison_snapshot(policy_identity)
    HostSnapshot.new(details: { "platform" => { "os_id" => "almalinux", "os_version" => "9.8", "architecture" => "x86_64" },
      "selinux" => { "policy_identity" => policy_identity, "configured_policy_type" => "targeted", "boolean_status" => "observed",
        "booleans" => [{ "name" => "httpd_can_network_connect", "current" => false, "status" => "observed" }],
        "policy" => { "port_inventory" => { "status" => "observed", "mappings" => [] } } } })
  end

  after do
    CatalogPolicyArtifact.delete_all
    DistributionCatalogImport.delete_all
    DistributionCatalogBoolean.delete_all
    DistributionCatalogPort.delete_all
    DistributionCatalogRevision.delete_all
    PolicyArtifact.delete_all
    clear_enqueued_jobs
  end

  [[], %w[postgresql_t rhcd_t]].each do |domains|
    it "imports #{domains.inspect} without companion bytes, jobs, or fabricated host evidence" do
      before = [Host, HostSnapshot, RawEvent, PolicyArtifact].map(&:count)
      expect(PolicyPermissiveDomainAnalyzer).not_to receive(:call)
      expect do
        record = revision(domains: domains)
        expect(record.reload.reference_permissive_domains).to include(status: "observed", domains: domains,
          provenance: "inline_catalog_extraction", semantics_version: 1, evaluator_version: "SETools 4.5.1",
          policy_identity: record.loaded_policy_digest, catalog_revision_id: record.id, content_digest: record.content_digest)
        expect(record.catalog_policy_artifact).to be_nil
        record.catalog_management.change!(lifecycle: "archived", changed_by: "test")
        expect(record.reference_permissive_domains[:domains]).to eq(domains)
      end.not_to have_enqueued_job(AnalyzePolicyPermissiveDomainsJob)
      expect([Host, HostSnapshot, RawEvent, PolicyArtifact].map(&:count)).to eq(before)
    end
  end

  it "does not fall back to a host cache for absent inline facts" do
    record = revision
    record.update_column(:effective_permissive_domains, nil)
    expect(PolicyPermissiveDomains).not_to receive(:lookup)
    expect(record.reference_permissive_domains).to include(status: "unavailable", reason: "reference_inline_facts_unavailable", domains: nil)
  end

  it "allows automatic family-agreement comparison with one complete inline family" do
    record = revision(domains: [])
    snapshot = HostSnapshot.new(details: { "platform" => { "os_id" => record.distribution, "os_version" => record.major_version, "architecture" => record.architecture },
      "selinux" => { "policy_identity" => record.loaded_policy_digest, "configured_policy_type" => record.policy_type } })
    exact = CatalogReferenceSelection.call(snapshot: snapshot)
    expect(exact.basis).to eq("exact_policy_identity")
    snapshot.details["selinux"]["policy_identity"] = "sha256:" + "f" * 64
    fallback = CatalogReferenceSelection.call(snapshot: snapshot)
    explicit = CatalogReferenceSelection.call(snapshot: snapshot, revision_id: record.id)
    expect(fallback.basis).to eq("major_release_family_agreement")
    [exact, fallback, explicit].each { |selection| expect(selection.family("effective_permissive_domains")).to include(status: "comparable", comparison_allowed: true) }
    expect(explicit.revision.reference_permissive_domains[:domains]).to eq([])
    expect(explicit.as_json[:equivalence_asserted]).to be(false)
    record.catalog_management.change!(lifecycle: "archived", changed_by: "test")
    expect(CatalogReferenceSelection.call(snapshot: snapshot, revision_id: record.id).reason).to eq("archived_reference")
  end

  it "requires every eligible major-release candidate to agree on compatible inline membership" do
    first = revision(domains: ["alpha_t"])
    second = revision("reference policy two", domains: ["beta_t"])
    host_snapshot = comparison_snapshot("sha256:" + "f" * 64)

    selection = CatalogReferenceSelection.call(snapshot: host_snapshot)
    expect(selection.basis).to eq("major_release_family_agreement")
    expect(selection.family("booleans")).to include(status: "comparable", comparison_allowed: true)
    expect(selection.family("effective_permissive_domains")).to include(status: "unknown", reference_status: "observed",
      comparison_allowed: false, reason: "effective_permissive_reference_ambiguous")

    second.update_column(:effective_permissive_domains, first.effective_permissive_domains)
    expect(CatalogReferenceSelection.call(snapshot: host_snapshot).family("effective_permissive_domains")).to include(status: "comparable", comparison_allowed: true)
  end

  it "fails closed for automatic effective comparison when an eligible legacy V3 candidate lacks inline facts" do
    record = revision
    legacy = DistributionCatalogRevision.create!(schema_version: 1, collector_semantics_version: 3,
      content_digest: "sha256:" + "b" * 64, loaded_policy_digest: "sha256:" + "c" * 64,
      distribution: "almalinux", major_version: "9", architecture: "x86_64", policy_type: "targeted",
      kernel_policy_version: 33, policy_packages: [], booleans_complete: true, ports_complete: true)
    record.distribution_catalog_booleans.each do |entry|
      legacy.distribution_catalog_booleans.create!(name: entry.name, default_value: entry.default_value, description: entry.description)
    end
    record.distribution_catalog_ports.each do |mapping|
      legacy.distribution_catalog_ports.create!(protocol: mapping.protocol, start_port: mapping.start_port, end_port: mapping.end_port, selinux_type: mapping.selinux_type)
    end
    host_snapshot = comparison_snapshot("sha256:" + "f" * 64)

    selection = CatalogReferenceSelection.call(snapshot: host_snapshot)
    expect(selection.basis).to eq("major_release_family_agreement")
    expect(selection.family("effective_permissive_domains")).to include(status: "unknown", reference_status: "incomplete",
      comparison_allowed: false, reason: "reference_inline_facts_unavailable")
    expect(record).to be_persisted
  end
end
