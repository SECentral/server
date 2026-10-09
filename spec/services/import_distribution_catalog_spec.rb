require "rails_helper"

RSpec.describe ImportDistributionCatalog do
  def document
    JSON.parse(File.read(Rails.root.join("spec/fixtures/catalogs/v3.json")))
  end

  def catalog_artifact(value = document)
    DistributionCatalogArtifact.new(JSON.generate(value))
  end

  def recalculate(value)
    value["content_digest"] = "sha256:#{Digest::SHA256.hexdigest(DistributionCatalogCanonicalizer.call(value.fetch("catalog")))}"
    value
  end

  around do |example|
    DistributionCatalogImport.delete_all
    DistributionCatalogBoolean.delete_all
    DistributionCatalogPort.delete_all
    DistributionCatalogRevision.delete_all
    example.run
    if @applicability_host
      RawEvent.where(host: @applicability_host).delete_all
      HostSnapshotObservation.where(host: @applicability_host).delete_all
      HostSnapshot.where(host: @applicability_host).delete_all
      AgentInstallation.where(organization: @applicability_organization).delete_all
      @applicability_host.delete
      @applicability_organization.delete
    end
    DistributionCatalogImport.delete_all
    DistributionCatalogBoolean.delete_all
    DistributionCatalogPort.delete_all
    DistributionCatalogRevision.delete_all
  end

  it "persists immutable normalized content and exact import bytes" do
    result = described_class.call(artifact: catalog_artifact, source_path: "catalog.json")
    revision = result.revision

    expect(result.created).to be(true)
    expect(revision.content_digest).to eq("sha256:3d8dff7fdef145ff2b0db34036d55248e97e6b33c231e5f6fe04d2ec19d3131d")
    expect(revision.collector_semantics_version).to eq(3)
    expect(revision.loaded_policy_digest).to eq("sha256:" + "a" * 64)
    expect(revision).to have_attributes(booleans_complete: true, ports_complete: true)
    expect(revision.distribution_catalog_booleans.map { |entry| { "name" => entry.name, "default" => entry.default_value, "description" => entry.description } }).to eq(document.dig("catalog", "families", "booleans", "entries"))
    expect(revision.distribution_catalog_ports.map { |entry| { "type" => entry.selinux_type, "protocol" => entry.protocol, "start" => entry.start_port, "end" => entry.end_port } }).to eq(document.dig("catalog", "families", "ports", "mappings"))
    expect(revision.port_catalog_completeness).to eq("tcp" => "complete", "udp" => "complete", "sctp" => "complete", "dccp" => "complete")
    expect(result.catalog_import.artifact).to eq(catalog_artifact.artifact.b)
    expect(result.catalog_import.acquisition_metadata).to include("collector_version" => "secentral-catalog-collector-v1")
    expect { revision.update!(distribution: "other") }.to raise_error(ActiveRecord::ReadOnlyRecord)
    expect { revision.distribution_catalog_booleans.first.update!(description: "other") }.to raise_error(ActiveRecord::ReadOnlyRecord)
    expect { revision.distribution_catalog_ports.first.destroy! }.to raise_error(ActiveRecord::ReadOnlyRecord)
    expect { result.catalog_import.update!(source_path: "other.json") }.to raise_error(ActiveRecord::ReadOnlyRecord)
  end

  it "reuses the revision and appends import evidence" do
    first = described_class.call(artifact: catalog_artifact, source_path: "first.json")
    second = described_class.call(artifact: catalog_artifact, source_path: "second.json")

    expect(second.created).to be(false)
    expect(second.revision).to eq(first.revision)
    expect(DistributionCatalogRevision.count).to eq(1)
    expect(first.revision.distribution_catalog_imports.count).to eq(2)

    first.revision.catalog_management.change!(display_name: "Operator label", lifecycle: "archived", changed_by: "operator")
    third = described_class.call(artifact: catalog_artifact, source_path: "third.json")
    expect(third.revision.catalog_management).to have_attributes(display_name: "Operator label", lifecycle: "archived")
    expect(third.revision).to eq(first.revision)
    expect(third.revision.distribution_catalog_imports.count).to eq(3)
  end

  it "rejects invalid input without persisting anything" do
    value = document
    value.dig("catalog", "families", "booleans", "entries") << value.dig("catalog", "families", "booleans", "entries").first.deep_dup
    value.dig("catalog", "families", "booleans", "entries").sort_by! { |entry| entry.fetch("name") }
    recalculate(value)

    expect { described_class.call(artifact: catalog_artifact(value)) }.to raise_error(DistributionCatalogArtifact::Invalid)
    expect(DistributionCatalogRevision.count).to eq(0)
    expect(DistributionCatalogImport.count).to eq(0)
  end

  it "rejects V1, V2, and bad V3 digests before persisting anything" do
    [1, 2].each do |version|
      value = document
      value.dig("catalog")["collector_semantics_version"] = version
      expect { described_class.call(artifact: catalog_artifact(value)) }.to raise_error(DistributionCatalogArtifact::Invalid)
    end
    value = document
    value["content_digest"] = "sha256:" + "0" * 64
    expect { described_class.call(artifact: catalog_artifact(value)) }.to raise_error(DistributionCatalogArtifact::Invalid)

    expect(DistributionCatalogRevision.count).to eq(0)
    expect(DistributionCatalogImport.count).to eq(0)
  end

  it "rolls back revision creation when normalized persistence fails" do
    allow_any_instance_of(described_class).to receive(:create_children).and_raise("write failed")

    expect { described_class.call(artifact: catalog_artifact) }.to raise_error("write failed")
    expect(DistributionCatalogRevision.count).to eq(0)
    expect(DistributionCatalogImport.count).to eq(0)
  end

  it "rejects conflicting semantic content for an existing loaded policy" do
    described_class.call(artifact: catalog_artifact)
    value = document
    value.dig("catalog", "families", "booleans", "entries", 0)["description"] = "changed"
    recalculate(value)

    expect { described_class.call(artifact: catalog_artifact(value)) }.to raise_error(described_class::Conflict)
    expect(DistributionCatalogRevision.count).to eq(1)
  end

  it "uses an event-linked historical snapshot rather than host current state" do
    revision = described_class.call(artifact: catalog_artifact).revision
    changed = document
    changed.dig("catalog", "policy")["loaded_policy_digest"] = "sha256:" + "b" * 64
    recalculate(changed)
    current_revision = described_class.call(artifact: catalog_artifact(changed)).revision
    @applicability_organization = Organization.create!(name: "catalog test #{SecureRandom.uuid}")
    organization = @applicability_organization
    @applicability_host = organization.hosts.create!(external_id: "catalog-test-#{SecureRandom.uuid}")
    host = @applicability_host
    historical = host.host_snapshots.create!(details: { "selinux" => { "policy_identity" => revision.loaded_policy_digest }, "platform" => { "os_id" => "different" } })
    current = host.host_snapshots.create!(details: { "selinux" => { "policy_identity" => current_revision.loaded_policy_digest } })
    unmatched = host.host_snapshots.create!(details: { "selinux" => { "policy_identity" => "sha256:" + "c" * 64, "policy" => { "package" => "selinux-policy-38.1" } }, "platform" => { "os_id" => revision.distribution, "os_version" => revision.major_version } })
    now = Time.current
    installation = organization.agent_installations.create!(name: "catalog-installation-#{SecureRandom.uuid}", bound_host: host)
    host.host_snapshot_observations.create!(host_snapshot: current, agent_installation: installation, first_observed_at: now, last_observed_at: now, first_received_at: now, last_received_at: now)
    event = organization.raw_events.create!(agent_installation: installation, host: host, host_snapshot: historical, audit_timestamp: now, audit_sequence: 1, boot_id: "catalog-boot", completion_reason: "eoe", evidence_digest: "sha256:" + "e" * 64, agent_received_at: now, host_observed_at: now, server_received_at: now, schema_version: 2)

    expect(host.current_snapshot).to eq(current)
    expect(DistributionCatalogRevision.for_snapshot(historical)).to eq(revision)
    expect(DistributionCatalogRevision.for_snapshot(current)).to eq(current_revision)
    expect(DistributionCatalogRevision.for_snapshot(event.host_snapshot)).to eq(revision)
    expect(DistributionCatalogReference.for_snapshot(event.host_snapshot).boolean_catalog.fetch("content_digest")).to eq(revision.content_digest)
    expect(DistributionCatalogRevision.for_snapshot(unmatched)).to be_nil
  end

  it "shares preview/import classification with CLI artifacts without persistence" do
    raw = File.binread(Rails.root.join("spec/fixtures/catalogs/v3.json"))
    before_counts = [DistributionCatalogRevision, DistributionCatalogImport, CatalogManagement].map(&:count)
    preview = described_class.preview(artifact: DistributionCatalogArtifact.new(raw), display_name: "Initial label")
    expect(preview.outcome).to eq("create_new_revision")
    expect([DistributionCatalogRevision, DistributionCatalogImport, CatalogManagement].map(&:count)).to eq(before_counts)
    result = described_class.call(artifact: DistributionCatalogArtifact.new(raw), display_name: "Initial label")
    expect(result.revision.content_digest).to eq(preview.artifact.content_digest)
    expect(result.revision.display_name).to eq(preview.display_name)
    expect(result.catalog_import.artifact).to eq(raw)
    expect(described_class.preview(artifact: DistributionCatalogArtifact.new(raw)).outcome).to eq("reuse_existing_revision")
  end

  it "rolls back if new management initialization fails" do
    allow_any_instance_of(DistributionCatalogRevision).to receive(:create_catalog_management!).and_raise("management failed")
    expect { described_class.call(artifact: catalog_artifact) }.to raise_error("management failed")
    expect([DistributionCatalogRevision, DistributionCatalogBoolean, DistributionCatalogPort, DistributionCatalogImport, CatalogManagement, CatalogManagementChange].map(&:count)).to eq([0, 0, 0, 0, 0, 0])
  end

  it "rolls back revision, families and management if import evidence cannot persist" do
    expect { described_class.call(artifact: catalog_artifact, source_kind: "invalid") }.to raise_error(ActiveRecord::RecordInvalid)
    expect([DistributionCatalogRevision, DistributionCatalogBoolean, DistributionCatalogPort, DistributionCatalogImport, CatalogManagement, CatalogManagementChange].map(&:count)).to eq([0, 0, 0, 0, 0, 0])
  end

  it "resolves simultaneous identical imports through shared deduplication after a uniqueness race" do
    ready = Queue.new
    start = Queue.new
    allow(DistributionCatalogRevision).to receive(:create!).and_wrap_original do |method, *args|
      ready << true
      start.pop
      method.call(*args)
    end
    raw = catalog_artifact.artifact
    threads = 2.times.map do
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          described_class.call(artifact: DistributionCatalogArtifact.new(raw), source_kind: "operator_upload", imported_by: "operator")
        end
      end
    end
    2.times { ready.pop }
    2.times { start << true }
    results = threads.map(&:value)
    expect(results.map(&:created)).to contain_exactly(true, false)
    expect(results.map { |result| result.revision.id }.uniq.size).to eq(1)
    expect([DistributionCatalogRevision, CatalogManagement, DistributionCatalogImport].map(&:count)).to eq([1, 1, 2])
    expect(DistributionCatalogImport.pluck(:artifact)).to eq([raw.b, raw.b])
  ensure
    2.times { start << true } if start
    threads&.each(&:join)
  end
end
