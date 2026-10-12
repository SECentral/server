require "rails_helper"
require "tempfile"

RSpec.describe AttachCatalogPolicy do
  include ActiveJob::TestHelper
  let(:bytes) { "\x00exact synthetic policy\xff".b }

  def revision(policy_bytes = bytes, description: nil)
    document = JSON.parse(File.binread(Rails.root.join("spec/fixtures/catalogs/v3.json")))
    document["catalog"]["policy"]["loaded_policy_digest"] = "sha256:#{Digest::SHA256.hexdigest(policy_bytes)}"
    document["catalog"]["families"]["booleans"]["entries"].first["description"] = description if description
    document["content_digest"] = "sha256:#{Digest::SHA256.hexdigest(DistributionCatalogCanonicalizer.call(document['catalog']))}"
    ImportDistributionCatalog.call(artifact: DistributionCatalogArtifact.new(JSON.generate(document))).revision
  end

  def attach(record, data = bytes, **options)
    described_class.call(revision: record, bytes: data, acquisition_basis: "Offline prepared reference capture", attached_by: "test-admin", **options)
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

  it "accepts exact binary bytes and persists an immutable association without host fabrication or extraction" do
    record = revision
    original = record.attributes
    counts = [Host, HostSnapshot, HostSnapshotObservation, RawEvent].map(&:count)
    expect { attach(record) }.not_to have_enqueued_job(AnalyzePolicyPermissiveDomainsJob)
    expect([Host, HostSnapshot, HostSnapshotObservation, RawEvent].map(&:count)).to eq(counts)
    state = DistributionCatalogRevision.find(record.id).reference_policy_artifact
    expect(state).to include(status: "available", content_digest: record.content_digest, expected_policy_digest: record.loaded_policy_digest, policy_artifact_digest: record.loaded_policy_digest, source_kind: "administrative_cli")
    expect(record.reload.attributes).to eq(original)
    expect(PolicyArtifact.first).to have_attributes(artifact: bytes, source_host_id: nil, permissive_domain_analysis: {})
    expect { record.catalog_policy_artifact.update!(acquisition_basis: "changed") }.to raise_error(ActiveRecord::ReadOnlyRecord)
    expect { PolicyArtifact.first.update!(artifact: "changed") }.to raise_error(ActiveRecord::ReadonlyAttributeError)
    expect { PolicyArtifact.first.destroy! }.to raise_error(ActiveRecord::DeleteRestrictionError)
  end

  it "rejects one-byte changes, incorrect revisions and oversize input before durable writes" do
    record = revision
    wrong = revision("other exact bytes")
    [bytes + "x", bytes.byteslice(0, bytes.bytesize - 1), "x" * (PolicyArtifact::MAX_BYTES + 1), ""].each do |data|
      expect { attach(record, data) }.to raise_error(PolicyArtifact::InvalidBytes)
    end
    expect { attach(wrong) }.to raise_error(PolicyArtifact::InvalidBytes, /digest mismatch/)
    expect(PolicyArtifact.count).to eq(0)
    expect(CatalogPolicyArtifact.count).to eq(0)
  end

  it "reuses content-addressed host bytes and makes identical association idempotent without replacing source" do
    record = revision
    policy = PolicyArtifact.store!(policy_identity: record.loaded_policy_digest, bytes: bytes, source_host_id: "real-original-host", defer_analysis: true)
    first = attach(record)
    original = first.attributes
    second = attach(record, acquisition_basis: "Another acquisition")
    expect(second.id).to eq(first.id)
    expect(second.attributes).to eq(original)
    expect(policy.reload.source_host_id).to eq("real-original-host")
    expect(PolicyArtifact.count).to eq(1)
    expect(CatalogPolicyArtifact.count).to eq(1)
  end

  it "rolls back blob creation when acquisition authority evidence is invalid" do
    record = revision
    expect { attach(record, acquisition_basis: "") }.to raise_error(ActiveRecord::RecordInvalid)
    expect(PolicyArtifact.count).to eq(0)
  end

  it "rejects a corrupt reused blob rather than replacing it" do
    record = revision
    PolicyArtifact.create!(policy_identity: record.loaded_policy_digest, artifact: "corrupt", artifact_size: 7, defer_analysis: true)
    expect { attach(record) }.to raise_error(PolicyArtifact::InvalidBytes, /digest mismatch/)
    expect(CatalogPolicyArtifact.count).to eq(0)
  end

  it "withholds companion availability if retained bytes are corrupted outside the immutable model" do
    record = revision
    companion = attach(record)
    PolicyArtifact.where(id: companion.policy_artifact_id).update_all(artifact: "corrupted")
    expect(record.reload.reference_policy_artifact).to include(status: "unavailable", reason: "reference_policy_artifact_invalid")
  end

  it "retains old companion and import evidence across archive/unarchive and a new revision" do
    old = revision
    companion = attach(old)
    imports = old.distribution_catalog_imports.map(&:attributes)
    old.catalog_management.change!(lifecycle: "archived", changed_by: "test")
    newer = revision("new policy")
    attach(newer, "new policy")
    expect(old.reload.reference_policy_artifact[:policy_artifact_id]).to eq(companion.policy_artifact_id)
    old.catalog_management.change!(lifecycle: "active", changed_by: "test")
    expect(old.distribution_catalog_imports.map(&:attributes)).to eq(imports)
    expect(old.reference_policy_artifact[:status]).to eq("available")
  end

  it "keeps legacy JSON-only families valid and reports companion unavailable without empty facts" do
    record = revision
    expect(record.reference_policy_artifact).to include(status: "unavailable", reason: "reference_policy_artifact_unavailable")
    expect(record.reference_policy_artifact).not_to have_key(:domains)
    expect(record.booleans_complete?).to be(true)
    expect(record.ports_complete?).to be(true)
    expect(DistributionCatalogDiff.call(record, record)[:booleans]).to be_present
  end

  it "keeps selection authority separate from companion availability for exact, fallback and explicit targets" do
    record = revision
    attach(record)
    platform = { "os_id" => record.distribution, "os_version" => record.major_version, "architecture" => record.architecture }
    snapshot = HostSnapshot.new(details: { "platform" => platform, "selinux" => { "policy_identity" => record.loaded_policy_digest, "configured_policy_type" => record.policy_type } })
    exact = CatalogReferenceSelection.call(snapshot: snapshot)
    expect(exact.basis).to eq("exact_policy_identity")
    expect(exact.revision.reference_policy_artifact[:status]).to eq("available")
    snapshot.details["selinux"]["policy_identity"] = "sha256:" + "f" * 64
    fallback = CatalogReferenceSelection.call(snapshot: snapshot)
    explicit = CatalogReferenceSelection.call(snapshot: snapshot, revision_id: record.id)
    expect(fallback.basis).to eq("major_release_family_agreement")
    expect(explicit.as_json[:equivalence_asserted]).to be(false)
    expect(explicit.revision.reference_policy_artifact[:policy_artifact_digest]).to eq(record.loaded_policy_digest)
    [exact, fallback, explicit].each { |selection| expect(selection.family("effective_permissive_domains")).to include(status: "unknown", comparison_allowed: false) }
    record.catalog_management.change!(lifecycle: "archived", changed_by: "test")
    expect(CatalogReferenceSelection.call(snapshot: snapshot, revision_id: record.id).reason).to eq("archived_reference")
  end

  it "treats malformed but SHA-matching binary as byte availability only, without parser execution" do
    record = revision
    expect(PolicyPermissiveDomainAnalyzer).not_to receive(:call)
    attach(record)
    expect(record.reload.reference_policy_artifact[:status]).to eq("available")
    expect(record.catalog_policy_artifact.policy_artifact.permissive_domain_analysis).to eq({})
  end

  it "reads bounded regular files and rejects symlinks, traversal, directories and oversize files" do
    Tempfile.create("reference-policy") do |file|
      file.binmode
      file.write(bytes)
      file.flush
      expect(described_class.read_file(file.path)).to eq(bytes)
      expect { described_class.read_file("#{File.dirname(file.path)}/../#{File.basename(File.dirname(file.path))}/#{File.basename(file.path)}") }.to raise_error(PolicyArtifact::InvalidBytes, /canonical/)
      link = "#{file.path}.link"
      File.symlink(file.path, link)
      expect { described_class.read_file(link) }.to raise_error(PolicyArtifact::InvalidBytes, /symlinks/)
      expect { described_class.read_file(File.dirname(file.path)) }.to raise_error(PolicyArtifact::InvalidBytes, /regular/)
      file.truncate(0)
      expect { described_class.read_file(file.path) }.to raise_error(PolicyArtifact::InvalidBytes, /size/)
      file.truncate(PolicyArtifact::MAX_BYTES + 1)
      expect { described_class.read_file(file.path) }.to raise_error(PolicyArtifact::InvalidBytes, /size/)
    ensure
      File.unlink(link) if link && File.symlink?(link)
    end
  end
end
