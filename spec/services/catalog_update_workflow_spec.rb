require "rails_helper"
require "open3"

RSpec.describe "Manual catalog update boundary" do
  after do
    DistributionCatalogImport.delete_all
    DistributionCatalogBoolean.delete_all
    DistributionCatalogPort.delete_all
    DistributionCatalogRevision.delete_all
  end

  def document(index, default: nil)
    value = JSON.parse(File.binread(Rails.root.join("spec/fixtures/catalogs/v3.json")))
    value["catalog"]["policy"]["loaded_policy_digest"] = "sha256:#{index.to_s(16).rjust(64, '0')}"
    value["catalog"]["families"]["booleans"]["entries"][0]["default"] = default unless default.nil?
    value["content_digest"] = "sha256:#{Digest::SHA256.hexdigest(DistributionCatalogCanonicalizer.call(value.fetch('catalog')))}"
    value
  end

  def import(value)
    ImportDistributionCatalog.call(artifact: DistributionCatalogArtifact.new(JSON.generate(value)))
  end

  def snapshot(identity)
    HostSnapshot.new(details: { "platform" => { "os_id" => "example", "os_version" => "9.1", "architecture" => "x86_64" }, "selinux" => { "policy_identity" => identity, "configured_policy_type" => "targeted" } })
  end

  it "retains old revisions while new exact/agreement/ambiguous evaluations and explicit targets remain distinct" do
    first = import(document(1))
    original = first.revision.attributes
    old_import = first.catalog_import.attributes
    unknown = snapshot("sha256:" + "f" * 64)
    agreed = import(document(2))
    expect(CatalogReferenceSelection.call(snapshot: unknown)).to have_attributes(status: "selected", basis: "major_release_family_agreement")
    expect(CatalogReferenceSelection.call(snapshot: snapshot(agreed.revision.loaded_policy_digest)).revision).to eq(agreed.revision)
    conflicting = import(document(3, default: !document(1).dig("catalog", "families", "booleans", "entries", 0, "default")))
    expect(CatalogReferenceSelection.call(snapshot: unknown).status).to eq("ambiguous")
    expect(CatalogReferenceSelection.call(snapshot: unknown, revision_id: first.revision.id)).to have_attributes(mode: "explicit", revision: first.revision)
    expect(first.revision.reload.attributes).to eq(original)
    expect(first.catalog_import.reload.attributes).to eq(old_import)
    expect([first.revision, agreed.revision, conflicting.revision].map { |record| record.catalog_management.lifecycle }).to eq(%w[active active active])
  end

  it "does not import or replace catalogs on database preparation or a fresh Rails boot" do
    result = import(document(1))
    result.revision.catalog_management.change!(lifecycle: "archived", changed_by: "test")
    original = [result.revision.attributes, result.catalog_import.attributes, result.revision.catalog_management.attributes]
    stdout, stderr, status = Open3.capture3("bundle", "exec", "rails", "db:prepare")
    expect(status.success?).to be(true), "#{stdout}\n#{stderr}"
    stdout, stderr, status = Open3.capture3("bundle", "exec", "rails", "runner", "puts JSON.generate([DistributionCatalogRevision.count, DistributionCatalogImport.count])")
    expect(status.success?).to be(true), stderr
    expect(JSON.parse(stdout.lines.last)).to eq([1, 1])
    expect([result.revision.reload.attributes, result.catalog_import.reload.attributes, result.revision.catalog_management.reload.attributes]).to eq(original)
  end
end
