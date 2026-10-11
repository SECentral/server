# Run only against a clean disposable test database, with retained real V3 bytes:
# rails runner script/catalog_distribution_update_acceptance.rb OLD_JSON NEW_JSON
raise "Use a clean disposable test database" unless Rails.env.test? && DistributionCatalogRevision.count.zero?
require "action_dispatch/testing/integration"

old_path, new_path = ARGV
raise "Provide retained older and newer real candidate paths" unless old_path && new_path
old_bytes = File.binread(old_path)
new_bytes = File.binread(new_path)
old_artifact = DistributionCatalogArtifact.new(old_bytes).validate!
new_artifact = DistributionCatalogArtifact.new(new_bytes).validate!
source = CatalogDistributionSource.verify(Rails.root.join("catalogs"))

ENV["ADMIN_USERNAME"] = "distribution-acceptance"
ENV["ADMIN_PASSWORD_DIGEST"] = BCrypt::Password.create("acceptance-only").to_s
Api::V1::BaseController.config.allow_forgery_protection = true
client = ActionDispatch::Integration::Session.new(Rails.application)
client.get("/api/v1/sessions")
client.post("/api/v1/sessions", params: { username: "distribution-acceptance", password: "acceptance-only" }, headers: { "X-CSRF-Token" => client.response.headers["X-CSRF-Token"] })
raise "Login failed" unless client.response.status == 201

def import_with_preview(client, bytes)
  original = [DistributionCatalogRevision, DistributionCatalogImport, CatalogManagement, CatalogManagementChange].map(&:count)
  client.post("/api/v1/catalogs/import-preview", params: bytes, headers: { "CONTENT_TYPE" => "application/octet-stream", "X-CSRF-Token" => client.response.headers["X-CSRF-Token"] })
  raise "Preview failed" unless client.response.status == 200
  token = JSON.parse(client.response.body).dig("preview", "preview_token")
  raise "Preview mutated catalog tables" unless [DistributionCatalogRevision, DistributionCatalogImport, CatalogManagement, CatalogManagementChange].map(&:count) == original
  client.post("/api/v1/catalogs/import-confirm", params: bytes, headers: { "CONTENT_TYPE" => "application/octet-stream", "X-CSRF-Token" => client.response.headers["X-CSRF-Token"], "X-Catalog-Preview" => token })
  raise "Confirmation failed" unless [200, 201].include?(client.response.status)
  JSON.parse(client.response.body)
end

first = import_with_preview(client, old_bytes)
old_revision = DistributionCatalogRevision.find(first.dig("catalog", "id"))
old_import = old_revision.distribution_catalog_imports.first
original_revision = old_revision.attributes
original_import = old_import.attributes
duplicate = import_with_preview(client, old_bytes)
raise "Duplicate changed identity" unless duplicate["outcome"] == "reuse_existing_revision" && duplicate.dig("catalog", "id") == old_revision.id
second = import_with_preview(client, new_bytes)
raise "New candidate not created" unless second["outcome"] == "create_new_revision"
new_revision = DistributionCatalogRevision.find(second.dig("catalog", "id"))
report = second.dig("catalog_import", "comparison_report")
raise "Unique real comparison missing" unless report["status"] == "compared" && report.dig("from_revision", "content_digest") == old_artifact.content_digest && report.dig("to_revision", "content_digest") == new_artifact.content_digest
raise "Old immutable evidence changed" unless old_revision.reload.attributes == original_revision && old_import.reload.attributes == original_import
raise "New bytes changed" unless new_revision.distribution_catalog_imports.first.artifact == new_bytes
raise "Import changed old lifecycle" unless old_revision.catalog_management.lifecycle == "active"

platform = new_artifact.catalog["platform"]
details = { "platform" => { "os_id" => platform["distribution"], "os_version" => platform["major_version"], "architecture" => platform["architecture"] }, "selinux" => { "policy_identity" => new_revision.loaded_policy_digest, "configured_policy_type" => new_revision.policy_type } }
snapshot = HostSnapshot.new(details: details)
raise "New exact not selected" unless CatalogReferenceSelection.call(snapshot: snapshot).revision == new_revision
snapshot.details["selinux"]["policy_identity"] = "sha256:" + "f" * 64
fallback = CatalogReferenceSelection.call(snapshot: snapshot)
raise "Explicit target was changed by import" unless CatalogReferenceSelection.call(snapshot: snapshot, revision_id: old_revision.id).revision == old_revision
old_revision.catalog_management.change!(lifecycle: "archived", changed_by: "distribution-acceptance")
raise "Archive destroyed old data" unless DistributionCatalogRevision.find(old_revision.id).content_digest == old_artifact.content_digest
raise "Archive did not resolve remaining fallback" unless CatalogReferenceSelection.call(snapshot: snapshot).revision == new_revision
puts JSON.pretty_generate(source_status: { supported: source.supported_count },
  old_digest: old_artifact.content_digest, new_digest: new_artifact.content_digest,
  old_raw_sha256: Digest::SHA256.hexdigest(old_bytes), new_raw_sha256: Digest::SHA256.hexdigest(new_bytes),
  duplicate_reused: true, old_evidence_retained: true, offline_local_files: true,
  comparison_report: report, selection_after_import: fallback.as_json, archive_explicit_retains_revision: true)
