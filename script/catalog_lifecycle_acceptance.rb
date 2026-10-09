# Run with `bundle exec rails runner script/catalog_lifecycle_acceptance.rb`.
# Uses retained catalogs and rolls management changes back; no host is modified.
def catalog_evidence(revision)
  {
    revision: revision.reload.attributes,
    booleans: revision.distribution_catalog_booleans.reload.map(&:attributes),
    ports: revision.distribution_catalog_ports.reload.map(&:attributes),
    imports: revision.distribution_catalog_imports.reload.map do |record|
      record.attributes.merge("artifact" => record.artifact.unpack1("H*"))
    end
  }
end

results = []
revisions = DistributionCatalogRevision.order(:id).to_a
raise "No retained catalogs to validate" if revisions.empty?

CatalogManagement.transaction do
  revisions.each do |revision|
    management = revision.catalog_management
    original_name = management.display_name
    original_lifecycle = management.lifecycle
    evidence = catalog_evidence(revision)
    snapshot_basis = HostSnapshot.where("details #>> '{selinux,policy_identity}' = ?", revision.loaded_policy_digest).order(:id).pluck(:id, :details)
    event_basis = RawEvent.where(host_snapshot_id: snapshot_basis.map(&:first)).order(:id).pluck(:id, :host_snapshot_id)
    snapshot = HostSnapshot.new(details: { "selinux" => { "policy_identity" => revision.loaded_policy_digest } })
    pin = DistributionCatalogReference.from_revision(revision).boolean_catalog.deep_dup

    management.change!(lifecycle: "active", changed_by: "slice-a-acceptance")
    raise "Active exact revision not selected" unless DistributionCatalogReference.for_snapshot(snapshot)&.revision == revision
    management.change!(display_name: "Acceptance #{revision.id}", changed_by: "slice-a-acceptance")
    raise "Rename changed immutable evidence" unless catalog_evidence(revision) == evidence
    management = revision.catalog_management
    management.change!(lifecycle: "archived", changed_by: "slice-a-acceptance")
    raise "Archived exact revision selected" if DistributionCatalogReference.for_snapshot(snapshot)
    raise "Archived policy overlay still selected" if DistributionCatalogReference.for_policy_identity(revision.loaded_policy_digest)
    raise "Retained identity lost" unless DistributionCatalogRevision.for_snapshot(snapshot) == revision
    raise "Pinned content changed" unless DistributionCatalogReference.from_revision(DistributionCatalogRevision.find(revision.id)).boolean_catalog == pin
    management.change!(lifecycle: "active", changed_by: "slice-a-acceptance")
    raise "Unarchive failed" unless DistributionCatalogReference.for_snapshot(snapshot)&.revision == revision
    raise "Management changed immutable evidence" unless catalog_evidence(revision) == evidence
    raise "Snapshot history changed" unless HostSnapshot.where(id: snapshot_basis.map(&:first)).order(:id).pluck(:id, :details) == snapshot_basis
    raise "Event snapshot links changed" unless RawEvent.where(id: event_basis.map(&:first)).order(:id).pluck(:id, :host_snapshot_id) == event_basis

    results << {
      revision_id: revision.id, distribution: revision.distribution,
      content_digest: revision.content_digest, loaded_policy_digest: revision.loaded_policy_digest,
      booleans: revision.distribution_catalog_booleans.size, ports: revision.distribution_catalog_ports.size,
      raw_artifact_sha256: revision.distribution_catalog_imports.map { |record| Digest::SHA256.hexdigest(record.artifact) },
      immutable_evidence_sha256: Digest::SHA256.hexdigest(JSON.generate(evidence)),
      preserved_snapshot_count: snapshot_basis.size, preserved_event_link_count: event_basis.size,
      original_name: original_name, original_lifecycle: original_lifecycle,
      rename_archive_unarchive: "passed"
    }
  end
  raise ActiveRecord::Rollback
end

results.each do |result|
  management = DistributionCatalogRevision.find(result[:revision_id]).catalog_management
  raise "Acceptance did not restore original management" unless management.display_name == result[:original_name] && management.lifecycle == result[:original_lifecycle]
end
puts JSON.pretty_generate(results)
