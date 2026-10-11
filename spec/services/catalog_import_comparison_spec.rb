require "rails_helper"

RSpec.describe CatalogImportComparison do
  after do
    DistributionCatalogImport.delete_all
    DistributionCatalogBoolean.delete_all
    DistributionCatalogPort.delete_all
    DistributionCatalogRevision.delete_all
  end

  def import(index, **options)
    document = JSON.parse(File.binread(Rails.root.join("spec/fixtures/catalogs/v3.json")))
    document["catalog"]["policy"]["loaded_policy_digest"] = "sha256:#{index.to_s(16).rjust(64, '0')}"
    yield document["catalog"] if block_given?
    document["content_digest"] = "sha256:#{Digest::SHA256.hexdigest(DistributionCatalogCanonicalizer.call(document.fetch('catalog')))}"
    ImportDistributionCatalog.call(artifact: DistributionCatalogArtifact.new(JSON.generate(document)), **options)
  end

  it "records no basis for a first import and keeps duplicate evidence distinct from new revision changes" do
    first = import(1)
    original_bytes = first.catalog_import.artifact
    expect(first.catalog_import.comparison_report).to include("status" => "none", "reason" => "no_comparable_revision")
    first.revision.catalog_management.change!(lifecycle: "archived", changed_by: "test")
    duplicate = ImportDistributionCatalog.call(artifact: DistributionCatalogArtifact.new(original_bytes))
    expect(duplicate.catalog_import.comparison_report).to include("status" => "not_applicable", "reason" => "duplicate_import")
    expect(duplicate.revision).to eq(first.revision)
    expect(first.revision.catalog_management.reload.lifecycle).to eq("archived")
  end

  it "includes an archived unique same-context basis and reports all existing comparator categories" do
    first = import(1)
    first.revision.catalog_management.change!(lifecycle: "archived", changed_by: "test")
    original = first.revision.attributes
    original_import = first.catalog_import.attributes
    second = import(2) do |catalog|
      entries = catalog["families"]["booleans"]["entries"]
      entries.pop
      entries[0]["default"] = !entries[0]["default"]
      entries[0]["description"] = "Changed description"
      entries << { "name" => "zz_added", "default" => false, "description" => "Added" }
      mappings = catalog["families"]["ports"]["mappings"]
      mappings[0]["type"] = "other_port_t"
    end
    report = second.catalog_import.comparison_report
    expect(report).to include("status" => "compared", "direction" => "existing_to_imported", "candidate_count" => 1)
    expect(report.dig("from_revision", "content_digest")).to eq(first.revision.content_digest)
    expect(report.dig("to_revision", "content_digest")).to eq(second.revision.content_digest)
    expect(report["changes"]["booleans"].transform_values { |value| value["count"] }).to eq("added" => 1, "removed" => 1, "default_changed" => 1, "description_changed" => 1)
    expect(report["changes"]["ports"].transform_values { |value| value["count"] }).to eq("added" => 1, "removed" => 1, "changed" => 1)
    expect(first.revision.reload.attributes).to eq(original)
    expect(first.catalog_import.reload.attributes).to eq(original_import)
    expect(first.revision.catalog_management.reload.lifecycle).to eq("archived")
    expect(second.revision.catalog_management.lifecycle).to eq("active")
  end

  it "does not choose among multiple bases by recency, lifecycle or equal family content" do
    first = import(1)
    second = import(2)
    first.revision.catalog_management.change!(lifecycle: "archived", changed_by: "test")
    third = import(3)
    report = third.catalog_import.comparison_report
    expect(report).to include("status" => "ambiguous", "reason" => "multiple_comparable_revisions", "candidate_count" => 2, "from_revision" => nil, "changes" => nil)
    expect(report["candidates"].map { |row| row["id"] }).to contain_exactly(first.revision.id, second.revision.id)
  end

  it "requires same major-release/architecture/type/schema context and caps samples" do
    import(1) { |catalog| catalog["platform"]["major_version"] = "8" }
    current = import(2)
    expect(current.catalog_import.comparison_report["status"]).to eq("none")
    newer = import(3) do |catalog|
      12.times { |index| catalog["families"]["booleans"]["entries"] << { "name" => "zz_added_#{index.to_s.rjust(2, '0')}", "default" => false, "description" => "Added" } }
    end
    added = newer.catalog_import.comparison_report.dig("changes", "booleans", "added")
    expect(added).to include("count" => 12, "truncated" => true)
    expect(added["samples"].size).to eq(10)
  end

  it "rolls back comparison/report evidence failures with the entire import" do
    first = import(1)
    allow(described_class).to receive(:call).and_raise("report failed")
    expect { import(2) }.to raise_error("report failed")
    expect(DistributionCatalogRevision.count).to eq(1)
    expect(DistributionCatalogImport.count).to eq(1)
    expect(first.revision.reload.content_digest).to eq(first.catalog_import.reload.comparison_report.dig("to_revision", "content_digest"))
  end
end
