# Run via Rails runner against retained development data. Controlled catalog and
# lifecycle changes roll back; captured snapshots are evaluated as captured,
# never represented as fresh live host state or a stored historical selection.
class CatalogSnapshotOracle
  attr_reader :id, :hostname, :current_state_observation

  def initialize(snapshot)
    @snapshot = snapshot
    @id = snapshot.host_id
    @hostname = snapshot.host.hostname
    @current_state_observation = Struct.new(:id, :host_snapshot, :stale?).new(nil, snapshot, false)
  end

  def selinux_state_for(*)
    CheckpointTrust.new(@snapshot).selinux
  end

  def port_inventory_for(*)
    CheckpointTrust.new(@snapshot).ports
  end
end

def selection_summary(snapshot, revision_id: nil)
  queries = []
  subscriber = ActiveSupport::Notifications.subscribe("sql.active_record") { |*, payload| queries << payload[:sql] if payload[:sql].start_with?("SELECT") }
  started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  comparison = HostConfigurationComparison.call(CatalogSnapshotOracle.new(snapshot), reference_revision_id: revision_id)
  {
    snapshot_id: snapshot.id, host_policy_identity: snapshot.details.dig("selinux", "policy_identity"),
    selection: comparison.selection.as_json,
    booleans: comparison.boolean_summary, ports: comparison.port_summary,
    selector_and_comparison_selects: queries.size,
    elapsed_ms: ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round(2)
  }
ensure
  ActiveSupport::Notifications.unsubscribe(subscriber) if subscriber
end

def selector_measurement(snapshot, revision_id: nil)
  CatalogReferenceSelection.call(snapshot: snapshot, revision_id: revision_id)
  queries = []
  subscriber = ActiveSupport::Notifications.subscribe("sql.active_record") { |*, payload| queries << payload[:sql] if payload[:sql].start_with?("SELECT") }
  started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  result = CatalogReferenceSelection.call(snapshot: snapshot, revision_id: revision_id)
  { status: result.status, basis: result.basis, selects: queries.size,
    elapsed_ms: ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round(2) }
ensure
  ActiveSupport::Notifications.unsubscribe(subscriber) if subscriber
end

almalinux = DistributionCatalogRevision.find_by!(distribution: "almalinux", major_version: "9")
rhel = DistributionCatalogRevision.find_by!(distribution: "rhel", major_version: "9")
exact = HostSnapshot.where("details #>> '{selinux,policy_identity}' = ?", almalinux.loaded_policy_digest).order(:id).last
fallback = HostSnapshot.where("details #>> '{platform,os_id}' = 'almalinux' AND details #>> '{platform,os_version}' LIKE '9.%'")
  .where("details #>> '{selinux,policy_identity}' IS NOT NULL AND details #>> '{selinux,policy_identity}' <> ?", almalinux.loaded_policy_digest)
  .where("details #>> '{selinux,boolean_status}' = 'observed' AND details #>> '{selinux,policy,port_inventory,status}' = 'observed'").order(:id).last
raise "Retained exact and nonexact snapshots required" unless exact && fallback

original_catalogs = DistributionCatalogRevision.order(:id).map { |record| [record.attributes, record.catalog_management.attributes, record.distribution_catalog_imports.map { |evidence| evidence.attributes.merge("artifact" => evidence.artifact.unpack1("H*")) }] }
original_snapshots = [exact.reload.attributes, fallback.reload.attributes]
original_hosts = Host.where(id: [exact.host_id, fallback.host_id]).order(:id).map(&:attributes)
results = {}
DistributionCatalogRevision.transaction do
  results[:exact] = selection_summary(exact)
  raise "Exact reference not selected" unless results[:exact][:selection][:basis] == "exact_policy_identity"
  results[:fallback] = selection_summary(fallback)
  raise "Fallback incorrectly identified" unless results[:fallback][:selection][:basis] == "major_release_family_agreement" && results[:fallback][:selection][:policy_identity_match] == false
  results[:explicit_nonexact] = selection_summary(exact, revision_id: rhel.id)
  raise "Explicit target was replaced" unless results[:explicit_nonexact][:selection][:selected_revision][:id] == rhel.id && results[:explicit_nonexact][:selection][:equivalence_asserted] == false
  results[:warm_selector] = { exact: selector_measurement(exact), fallback: selector_measurement(fallback), explicit: selector_measurement(exact, revision_id: rhel.id) }

  altered_package = HostSnapshot.new(host_id: fallback.host_id, details: fallback.details.deep_dup)
  altered_package.details["selinux"]["policy"]["package"] = { "name" => "not-a-selector", "version" => "999" }
  raise "Package-only fallback introduced" unless CatalogReferenceSelection.call(snapshot: altered_package).revision == almalinux

  # A distinct controlled artifact, never an edit to a retained revision.
  controlled = JSON.parse(File.binread(Rails.root.join("spec/fixtures/catalogs/v3.json")))
  controlled["catalog"]["platform"]["distribution"] = "almalinux"
  controlled["catalog"]["policy"]["loaded_policy_digest"] = "sha256:" + "e" * 64
  controlled["content_digest"] = "sha256:#{Digest::SHA256.hexdigest(DistributionCatalogCanonicalizer.call(controlled.fetch('catalog')))}"
  fixture = ImportDistributionCatalog.call(artifact: DistributionCatalogArtifact.new(JSON.generate(controlled))).revision
  ambiguous = CatalogReferenceSelection.call(snapshot: fallback)
  raise "Conflicting family candidates not ambiguous" unless ambiguous.status == "ambiguous"
  results[:controlled_ambiguity] = ambiguous.as_json
  fixture.catalog_management.change!(lifecycle: "archived", changed_by: "selection-acceptance")
  raise "Archiving incompatible candidate did not restore agreement" unless CatalogReferenceSelection.call(snapshot: fallback).revision == almalinux

  almalinux.catalog_management.change!(lifecycle: "archived", changed_by: "selection-acceptance")
  raise "Archived exact selected automatically" if CatalogReferenceSelection.call(snapshot: exact).revision
  archived = CatalogReferenceSelection.call(snapshot: exact, revision_id: almalinux.id)
  raise "Archived explicit selection substituted" unless archived.status == "unavailable" && archived.reason == "archived_reference"
  raise "Historical exact identity lost" unless DistributionCatalogRevision.for_snapshot(exact).id == almalinux.id
  raise "Retained adapter lost" unless DistributionCatalogReference.from_revision(almalinux).boolean_catalog.fetch("content_digest") == almalinux.content_digest
  results[:archived_explicit] = archived.as_json
  almalinux.catalog_management.change!(lifecycle: "active", changed_by: "selection-acceptance")
  raise "Unarchive failed" unless CatalogReferenceSelection.call(snapshot: exact).revision.id == almalinux.id
  results[:restored_exact] = true
  raise ActiveRecord::Rollback
end

after_catalogs = DistributionCatalogRevision.order(:id).map { |record| [record.attributes, record.catalog_management.attributes, record.distribution_catalog_imports.map { |evidence| evidence.attributes.merge("artifact" => evidence.artifact.unpack1("H*")) }] }
raise "Catalog/import/management changed" unless after_catalogs == original_catalogs
raise "Retained snapshots changed" unless [exact.reload.attributes, fallback.reload.attributes] == original_snapshots
raise "Host preference/state changed" unless Host.where(id: [exact.host_id, fallback.host_id]).order(:id).map(&:attributes) == original_hosts
puts JSON.pretty_generate(results)
