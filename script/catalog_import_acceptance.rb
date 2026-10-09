# Run in a disposable test database with copies of retained catalog tables:
# bundle exec rails runner script/catalog_import_acceptance.rb
raise "Use a disposable test database" unless Rails.env.test?
require "action_dispatch/testing/integration"

ENV["ADMIN_USERNAME"] = "catalog-acceptance"
ENV["ADMIN_PASSWORD_DIGEST"] = BCrypt::Password.create("acceptance-only").to_s
Api::V1::BaseController.config.allow_forgery_protection = true
client = ActionDispatch::Integration::Session.new(Rails.application)
client.get("/api/v1/sessions")
client.post("/api/v1/sessions", params: { username: "catalog-acceptance", password: "acceptance-only" }, headers: { "X-CSRF-Token" => client.response.headers["X-CSRF-Token"] })
raise "Login failed" unless client.response.status == 201

def catalog_counts
  [DistributionCatalogRevision, DistributionCatalogBoolean, DistributionCatalogPort, DistributionCatalogImport, CatalogManagement, CatalogManagementChange].map(&:count)
end

def upload_catalog(client, action, bytes, name: nil, token: nil)
  query = name.nil? ? "" : "?display_name=#{ERB::Util.url_encode(name)}"
  client.post("/api/v1/catalogs/import-#{action}#{query}", params: bytes, headers: { "CONTENT_TYPE" => "application/octet-stream", "X-CSRF-Token" => client.response.headers["X-CSRF-Token"], "X-Catalog-Preview" => token })
  JSON.parse(client.response.body)
end

retained = DistributionCatalogRevision.order(:id).to_a
raise "Retained AlmaLinux/RHEL catalogs required" unless retained.map(&:distribution).include?("almalinux") && retained.map(&:distribution).include?("rhel")
results = []
retained.each do |revision|
  original = revision.attributes
  original_import = revision.distribution_catalog_imports.first
  original_import_attributes = original_import.attributes
  bytes = original_import.artifact
  families = [revision.distribution_catalog_booleans.map(&:attributes), revision.distribution_catalog_ports.map(&:attributes)]
  revision.catalog_management.change!(display_name: "Retained #{revision.id}", lifecycle: "archived", changed_by: "catalog-acceptance")
  before = catalog_counts
  preview = upload_catalog(client, "preview", bytes, name: "Ignored submitted label").fetch("preview")
  raise "Preview writes or wrong reuse" unless catalog_counts == before && preview["outcome"] == "reuse_existing_revision" && preview.dig("existing_revision", "lifecycle") == "archived" && preview["display_name"] == "Retained #{revision.id}"
  result = upload_catalog(client, "confirm", bytes, token: preview.fetch("preview_token"))
  raise "Duplicate confirmation failed" unless client.response.status == 200 && result["outcome"] == "reuse_existing_revision"
  imported = DistributionCatalogImport.find(result.dig("catalog_import", "id"))
  raise "Raw upload/source changed" unless imported.artifact == bytes && imported.source_kind == "operator_upload" && imported.imported_by == "catalog-acceptance" && imported.source_path.nil?
  raise "Existing evidence changed" unless revision.reload.attributes == original && original_import.reload.attributes == original_import_attributes && families == [revision.distribution_catalog_booleans.reload.map(&:attributes), revision.distribution_catalog_ports.reload.map(&:attributes)]
  raise "Management changed by reimport" unless revision.catalog_management.display_name == "Retained #{revision.id}" && revision.catalog_management.lifecycle == "archived" && CatalogManagementChange.count == before.last
  results << { revision_id: revision.id, distribution: revision.distribution, content_digest: revision.content_digest, raw_sha256: Digest::SHA256.hexdigest(bytes), preview_pure: true, archived_renamed_reuse: true, exact_import_bytes: true }
end

# Clean candidate state for the known V3 fixture: no matching revision or policy.
bytes = File.binread(Rails.root.join("spec/fixtures/catalogs/v3.json"))
artifact = DistributionCatalogArtifact.new(bytes).validate!
raise "Fixture is not a new candidate" if DistributionCatalogRevision.exists?(content_digest: artifact.content_digest)
before = catalog_counts
preview = upload_catalog(client, "preview", bytes, name: "Acceptance new reference").fetch("preview")
raise "Create preview changed state" unless preview["outcome"] == "create_new_revision" && catalog_counts == before
result = upload_catalog(client, "confirm", bytes, token: preview.fetch("preview_token"))
raise "Create failed" unless client.response.status == 201 && result["outcome"] == "create_new_revision"
raise "Fixture byte identity changed" unless DistributionCatalogImport.find(result.dig("catalog_import", "id")).artifact == bytes

controlled = JSON.parse(bytes)
controlled.dig("catalog", "families", "booleans", "entries", 0)["description"] = "Controlled acceptance conflict"
controlled["content_digest"] = "sha256:#{Digest::SHA256.hexdigest(DistributionCatalogCanonicalizer.call(controlled.fetch('catalog')))}"
before = catalog_counts
conflict = upload_catalog(client, "preview", JSON.generate(controlled)).fetch("preview")
raise "Conflict preview changed state or offered confirm" unless conflict["outcome"] == "conflict" && conflict["preview_token"].nil? && catalog_counts == before
puts JSON.pretty_generate(retained_artifacts: results, disposable_new_candidate: { content_digest: artifact.content_digest, preview_pure: true, created: true, exact_import_bytes: true }, controlled_conflict: "rejected without persistence")
