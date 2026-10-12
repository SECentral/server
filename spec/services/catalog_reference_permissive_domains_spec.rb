require "rails_helper"

RSpec.describe "Catalog reference effective permissive extraction" do
  include ActiveJob::TestHelper

  def revision(bytes = "reference policy")
    document = JSON.parse(File.binread(Rails.root.join("spec/fixtures/catalogs/v3.json")))
    document["catalog"]["policy"]["loaded_policy_digest"] = "sha256:#{Digest::SHA256.hexdigest(bytes)}"
    document["content_digest"] = "sha256:#{Digest::SHA256.hexdigest(DistributionCatalogCanonicalizer.call(document['catalog']))}"
    ImportDistributionCatalog.call(artifact: DistributionCatalogArtifact.new(JSON.generate(document))).revision
  end

  def companion(record, bytes = "reference policy", domains: nil)
    policy = PolicyArtifact.store!(policy_identity: record.loaded_policy_digest, bytes: bytes, defer_analysis: true)
    if domains
      policy.update_column(:permissive_domain_analysis, { "status" => "observed", "domains" => domains,
        "policy_identity" => policy.policy_identity, "semantics_version" => PolicyPermissiveDomainAnalyzer::SEMANTICS_VERSION,
        "evaluator_version" => "SETools test", "evaluated_at" => Time.current.iso8601 })
    end
    AttachCatalogPolicy.call(revision: record, bytes: bytes, acquisition_basis: "Synthetic offline reference")
    policy
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

  it "requires explicit companion authority, not raw blob existence, and preserves legacy families" do
    record = revision
    PolicyArtifact.store!(policy_identity: record.loaded_policy_digest, bytes: "reference policy", defer_analysis: true)
    expect(record.reference_permissive_domains).to include(status: "unavailable", reason: "reference_policy_artifact_unavailable", domains: nil)
    expect(record.booleans_complete? && record.ports_complete?).to be(true)
  end

  it "enqueues once on first consumer without parsing or fabricating host evidence" do
    record = revision
    policy = companion(record)
    before = [Host, HostSnapshot, RawEvent].map(&:count)
    expect(PolicyPermissiveDomainAnalyzer).not_to receive(:call)
    expect { 2.times { expect(record.reference_permissive_domains).to include(status: "pending", domains: nil) } }.to have_enqueued_job(AnalyzePolicyPermissiveDomainsJob).with(policy.id, 1).exactly(:once)
    expect([Host, HostSnapshot, RawEvent].map(&:count)).to eq(before)
  end

  [[], %w[postgresql_t rhcd_t]].each do |domains|
    it "reuses current host-derived #{domains.inspect} cache without reparse and keeps archived facts" do
      record = revision
      policy = companion(record, domains: domains)
      expect(PolicyPermissiveDomainAnalyzer).not_to receive(:call)
      expect { expect(record.reference_permissive_domains).to include(status: "observed", domains: domains, evaluator_version: "SETools test", semantics_version: 1) }.not_to have_enqueued_job(AnalyzePolicyPermissiveDomainsJob)
      expect(PolicyPermissiveDomains.lookup(policy.policy_identity)).to include(status: "observed", domains: domains)
      record.catalog_management.change!(lifecycle: "archived", changed_by: "test")
      expect(record.reference_permissive_domains).to include(status: "observed", domains: domains)
    end
  end

  it "persists job results, distinguishing observed empty, failure, unavailable and explicit retry" do
    record = revision
    policy = companion(record)
    [{ "status" => "observed", "domains" => [], "evaluator_version" => "SETools test" },
     { "status" => "error", "error_message" => "runtime/resource bound" },
     { "status" => "unavailable", "error_message" => "parser unavailable" }].each do |result|
      policy.update_column(:permissive_domain_analysis, {})
      allow(PolicyPermissiveDomainAnalyzer).to receive(:call).and_return(result)
      expect(record.reference_permissive_domains[:status]).to eq("pending")
      perform_enqueued_jobs
      expect(record.reference_permissive_domains).to include(status: result["status"], domains: result["status"] == "observed" ? [] : nil)
      expect { record.reference_permissive_domains }.not_to have_enqueued_job(AnalyzePolicyPermissiveDomainsJob)
    end
  end

  it "reextracts incompatible semantics and prevents stale jobs or older workers from overwriting newer results" do
    record = revision
    policy = companion(record, domains: ["rhcd_t"])
    policy.update_column(:permissive_domain_analysis, policy.permissive_domain_analysis.merge("semantics_version" => 0))
    expect(record.reference_permissive_domains).to include(status: "pending", domains: nil)
    pending = policy.reload.permissive_domain_analysis
    AnalyzePolicyPermissiveDomainsJob.perform_now(policy.id, 0)
    expect(policy.reload.permissive_domain_analysis).to eq(pending)
    newer = pending.merge("status" => "observed", "semantics_version" => 2, "domains" => [], "evaluator_version" => "SETools future")
    policy.update_column(:permissive_domain_analysis, newer)
    expect(record.reference_permissive_domains).to include(status: "unavailable", domains: nil)
    AnalyzePolicyPermissiveDomainsJob.perform_now(policy.id, 1)
    expect(policy.reload.permissive_domain_analysis).to eq(newer)
    policy.invalidate_permissive_domain_analysis!("corrupt bytes")
    expect(policy.reload.permissive_domain_analysis).to include("status" => "unavailable", "semantics_version" => 2)
  end

  it "never shares facts across different SHA and withholds corrupt backing bytes from host and reference" do
    first = revision
    companion(first, domains: ["rhcd_t"])
    other = revision("other bytes")
    policy = companion(other, "other bytes", domains: [])
    expect(first.reference_permissive_domains[:domains]).to eq(["rhcd_t"])
    PolicyArtifact.where(id: policy.id).update_all(artifact: "corrupt")
    expect(PolicyPermissiveDomains.lookup(policy.policy_identity)).to include(status: "unavailable", domains: nil)
    expect(other.reference_permissive_domains).to include(status: "unavailable", domains: nil, reason: "reference_policy_artifact_invalid")
    expect(first.reference_permissive_domains[:domains]).to eq(["rhcd_t"])
  end

  it "does not grant selection applicability to observed reference facts" do
    record = revision
    companion(record, domains: [])
    snapshot = HostSnapshot.new(details: { "platform" => { "os_id" => record.distribution, "os_version" => record.major_version, "architecture" => record.architecture },
      "selinux" => { "policy_identity" => record.loaded_policy_digest, "configured_policy_type" => record.policy_type } })
    exact = CatalogReferenceSelection.call(snapshot: snapshot)
    expect(exact.basis).to eq("exact_policy_identity")
    expect(exact.revision.reference_permissive_domains[:status]).to eq("observed")
    snapshot.details["selinux"]["policy_identity"] = "sha256:" + "f" * 64
    fallback = CatalogReferenceSelection.call(snapshot: snapshot)
    explicit = CatalogReferenceSelection.call(snapshot: snapshot, revision_id: record.id)
    expect(fallback.basis).to eq("major_release_family_agreement")
    [exact, fallback, explicit].each { |selection| expect(selection.family("effective_permissive_domains")).to include(status: "unknown", comparison_allowed: false) }
    expect(explicit.revision.reference_permissive_domains[:domains]).to eq([])
    expect(explicit.as_json[:equivalence_asserted]).to be(false)
    record.catalog_management.change!(lifecycle: "archived", changed_by: "test")
    expect(CatalogReferenceSelection.call(snapshot: snapshot, revision_id: record.id).reason).to eq("archived_reference")
  end
end
