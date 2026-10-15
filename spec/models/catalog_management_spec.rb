require "rails_helper"

RSpec.describe CatalogManagement do
  let(:revision) do
    ImportDistributionCatalog.call(artifact: DistributionCatalogArtifact.read(Rails.root.join("spec/fixtures/catalogs/v4.json"))).revision
  end

  after do
    DistributionCatalogImport.delete_all
    DistributionCatalogBoolean.delete_all
    DistributionCatalogPort.delete_all
    DistributionCatalogRevision.delete_all
  end

  def evidence(revision)
    revision.reload.attributes.merge(
      "imports" => revision.distribution_catalog_imports.reload.map(&:attributes),
      "booleans" => revision.distribution_catalog_booleans.reload.map(&:attributes),
      "ports" => revision.distribution_catalog_ports.reload.map(&:attributes)
    )
  end

  it "creates default active management, preserves evidence through changes, and permits duplicate names" do
    original = evidence(revision)
    management = revision.catalog_management
    expect(management).to have_attributes(display_name: "Example 9", lifecycle: "active")

    management.change!(display_name: "  RHEL + Oracle  ", changed_by: "operator")
    management.change!(lifecycle: "archived", changed_by: "operator")
    management.change!(lifecycle: "archived", changed_by: "operator")
    management.change!(lifecycle: "active", changed_by: "operator")

    expect(revision.reload.display_name).to eq("RHEL + Oracle")
    expect(evidence(revision)).to eq(original)
    expect(management.catalog_management_changes.count).to eq(3)
    expect(management.catalog_management_changes.first).to have_attributes(previous_display_name: "Example 9", display_name: "RHEL + Oracle", changed_by: "operator")
    expect { revision.update!(content_digest: "other") }.to raise_error(ActiveRecord::ReadOnlyRecord)
    expect { management.destroy! }.to raise_error(ActiveRecord::ReadOnlyRecord)
    expect { management.catalog_management_changes.first.update!(display_name: "other") }.to raise_error(ActiveRecord::ReadOnlyRecord)
    expect(CatalogManagement.new(distribution_catalog_revision: revision, display_name: "RHEL + Oracle", lifecycle: "active")).to be_valid
  end

  it "rejects blank, oversized and control-character names and rolls back without evidence changes" do
    management = revision.catalog_management
    [" ", "a" * 121, "line\nname", "tab\tname"].each do |name|
      expect { management.change!(display_name: name, changed_by: "operator") }.to raise_error(ActiveRecord::RecordInvalid)
      expect(management.reload.display_name).to eq("Example 9")
    end
    expect(management.catalog_management_changes).to be_empty
  end

  it "rolls back the management write if audit persistence fails" do
    management = revision.catalog_management
    expect { management.change!(display_name: "changed", changed_by: "") }.to raise_error(ActiveRecord::RecordInvalid)
    expect(management.reload.display_name).to eq("Example 9")
  end

  it "serializes simultaneous renames, recording both and accepting the last serialized name" do
    id = revision.catalog_management.id
    ready = Queue.new
    start = Queue.new
    threads = %w[first second].map do |name|
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          management = described_class.find(id)
          ready << true
          start.pop
          management.change!(display_name: name, changed_by: name)
        end
      end
    end
    2.times { ready.pop }
    2.times { start << true }
    threads.each(&:value)
    management = described_class.find(id)
    changes = management.catalog_management_changes.to_a
    expect(changes.size).to eq(2)
    expect(changes.last.previous_display_name).to eq(changes.first.display_name)
    expect(management.display_name).to eq(changes.last.display_name)
  end

  it "does not lose a concurrent archive when a stale management instance renames" do
    id = revision.catalog_management.id
    ready = Queue.new
    start = Queue.new
    threads = [{ display_name: "New label" }, { lifecycle: "archived" }].map do |attributes|
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          management = described_class.find(id)
          ready << true
          start.pop
          management.change!(**attributes, changed_by: "operator")
        end
      end
    end
    2.times { ready.pop }
    2.times { start << true }
    threads.each(&:value)
    expect(described_class.find(id)).to have_attributes(display_name: "New label", lifecycle: "archived")
  end
end
