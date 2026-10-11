# Disposable test DB only. Reads an existing development blob without modifying it.
# REFERENCE_SOURCE_DATABASE_URL=... bundle exec rails runner script/catalog_policy_companion_acceptance.rb
raise "Use an empty disposable test database" unless Rails.env.test? && DistributionCatalogRevision.count.zero? && Host.count.zero?
require "pg"
require "tempfile"
require "rake"
require "open3"

path = Rails.root.join("catalogs").glob("**/*.review.json").sort.first.sub_ext("").sub_ext(".json")
CatalogDistributionSource.verify(Rails.root.join("catalogs"))
json = DistributionCatalogArtifact.read(path).validate!
expected = json.catalog.dig("policy", "loaded_policy_digest")
source = PG.connect(ENV.fetch("REFERENCE_SOURCE_DATABASE_URL"))
source.exec("BEGIN READ ONLY")
row = source.exec_params("SELECT id, artifact, artifact_size, source_host_id FROM policy_artifacts WHERE policy_identity = $1", [expected]).first
raise "No retained exact companion; collect JSON and /sys/fs/selinux/policy together" unless row
bytes = PG::Connection.unescape_bytea(row.fetch("artifact"))
PolicyArtifact.validate_bytes!(expected, bytes)
source.exec("ROLLBACK")
source.close

# Exercise upgrade of a retained JSON-only revision, not just an empty schema.
require Rails.root.join("db/migrate/20261011000002_create_catalog_policy_artifacts")
CreateCatalogPolicyArtifacts.new.migrate(:down)
revision = ImportDistributionCatalog.call(artifact: json, source_kind: "administrative_cli").revision
original_revision = revision.attributes
original_import = revision.distribution_catalog_imports.first.attributes
CreateCatalogPolicyArtifacts.new.migrate(:up)
CatalogPolicyArtifact.reset_column_information
raise "Migration rewrote catalog evidence" unless revision.reload.attributes == original_revision && revision.distribution_catalog_imports.first.reload.attributes == original_import
raise "Migration fabricated authority" unless CatalogPolicyArtifact.count.zero? && revision.reference_policy_artifact[:reason] == "reference_policy_artifact_unavailable"

begin
  AttachCatalogPolicy.call(revision: revision, bytes: bytes + "x", acquisition_basis: "Mismatch rejection control")
  raise "Mismatch was accepted"
rescue PolicyArtifact::InvalidBytes
  raise "Mismatch left durable evidence" unless PolicyArtifact.count.zero? && CatalogPolicyArtifact.count.zero?
end
Rails.application.load_tasks
Tempfile.create(["reference-companion", ".bin"]) do |file|
  file.binmode
  file.write(bytes)
  file.flush
  Rake::Task["secentral:catalog:attach_policy"].invoke(revision.id, file.path, "Explicit offline copy of retained reference-system exact policy artifact")
end
association = revision.reload.catalog_policy_artifact
original_association = association.attributes
raise "Reference creation parsed policy" unless association.policy_artifact.permissive_domain_analysis.empty?
duplicate = AttachCatalogPolicy.call(revision: revision, bytes: bytes, acquisition_basis: "Duplicate must preserve original source")
raise "Duplicate rewrote association" unless duplicate.attributes == original_association
raise "Host evidence fabricated" unless [Host, HostSnapshot, HostSnapshotObservation, RawEvent].all? { |model| model.count.zero? }
revision.catalog_management.change!(lifecycle: "archived", changed_by: "acceptance")
raise "Archive lost bytes" unless revision.reload.reference_policy_artifact[:status] == "available" && association.policy_artifact.reload.artifact == bytes
revision.catalog_management.change!(lifecycle: "active", changed_by: "acceptance")
raise "Boolean/port contents changed" unless DistributionCatalogDiff.call(revision, revision).values_at(:booleans, :ports).all? { |family| family.values.all?(&:empty?) }
raise "Import evidence changed" unless revision.distribution_catalog_imports.first.reload.attributes == original_import

output, status = Open3.capture2e("bundle", "exec", "rails", "db:prepare")
raise "Database prepare failed: #{output}" unless status.success?
check = "r = DistributionCatalogRevision.find(#{revision.id}); raise unless r.reference_policy_artifact[:status] == 'available' && r.reference_policy_artifact[:policy_artifact_digest] == #{expected.inspect}; raise unless CatalogPolicyArtifact.count == 1 && Host.count == 0; puts 'companion persisted'"
output, status = Open3.capture2e("bundle", "exec", "rails", "runner", check)
raise "Restart lost companion: #{output}" unless status.success? && output.strip == "companion persisted"
puts JSON.pretty_generate(content_digest: json.content_digest, expected_policy_digest: expected,
  actual_policy_digest: "sha256:#{Digest::SHA256.hexdigest(bytes)}", policy_size: bytes.bytesize,
  retained_source_artifact_id: row["id"], retained_source_host_id: row["source_host_id"],
  association: revision.reload.reference_policy_artifact, mismatch_rejected: true, idempotent: true,
  no_host_fabrication: true, migration_preserved_json: true, archive_retained: true, restart_retained: true,
  booleans_ports_unchanged: true, no_reference_extraction: true)
