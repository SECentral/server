# Run against a clean disposable test DB; only the final reviewed tree is input.
# bundle exec rails runner script/catalog_supported_source_acceptance.rb [catalogs/.../digest.json]
raise "Use a clean disposable test database" unless Rails.env.test? && DistributionCatalogRevision.count.zero?
require "action_dispatch/testing/integration"
require "rake"
require "tempfile"
require "open3"

source = CatalogDistributionSource.verify(Rails.root.join("catalogs"))
raise "No supported source artifact" unless source.supported_count >= 1
artifact_path = ARGV.first ? Rails.root.join(ARGV.first) : Rails.root.join("catalogs").glob("**/*.review.json").sort.first.sub_ext("").sub_ext(".json")
artifact_path = artifact_path.cleanpath
raise "Artifact is not in the reviewed source tree" unless Rails.root.join("catalogs").glob("**/*.review.json").include?(artifact_path.sub_ext(".review.json"))
relative = artifact_path.relative_path_from(Rails.root).to_s
review_path = artifact_path.sub_ext(".review.json")
bytes = artifact_path.binread
artifact = DistributionCatalogArtifact.new(bytes).validate!
record = JSON.parse(review_path.binread)
raise "Review/source identity mismatch" unless record["content_digest"] == artifact.content_digest

Rails.application.load_tasks
Tempfile.create(["offline-reviewed-catalog", ".json"]) do |copy|
  copy.binmode
  copy.write(bytes)
  copy.flush
  raise "Offline copy changed" unless File.binread(copy.path) == bytes
  Rake::Task["secentral:catalog:validate"].invoke(copy.path)
  Rake::Task["secentral:catalog:import"].invoke(copy.path)
end
revision = DistributionCatalogRevision.find_by!(content_digest: artifact.content_digest)
original_revision = revision.attributes
original_import = revision.distribution_catalog_imports.first.attributes
original_management = revision.catalog_management.attributes
raise "CLI did not preserve source bytes" unless original_import["artifact"] == bytes

ENV["ADMIN_USERNAME"] = "supported-source-acceptance"
ENV["ADMIN_PASSWORD_DIGEST"] = BCrypt::Password.create("acceptance-only").to_s
Api::V1::BaseController.config.allow_forgery_protection = true
client = ActionDispatch::Integration::Session.new(Rails.application)
client.get("/api/v1/sessions")
client.post("/api/v1/sessions", params: { username: "supported-source-acceptance", password: "acceptance-only" }, headers: { "X-CSRF-Token" => client.response.headers["X-CSRF-Token"] })
raise "Login failed" unless client.response.status == 201
before = [DistributionCatalogRevision, DistributionCatalogBoolean, DistributionCatalogPort, DistributionCatalogImport, CatalogManagement, CatalogManagementChange].map(&:count)
client.post("/api/v1/catalogs/import-preview?display_name=Ignored%20duplicate%20name", params: bytes, headers: { "CONTENT_TYPE" => "application/octet-stream", "X-CSRF-Token" => client.response.headers["X-CSRF-Token"] })
raise "Preview failed" unless client.response.status == 200
preview = JSON.parse(client.response.body).fetch("preview")
raise "Preview not a pure reuse" unless preview["outcome"] == "reuse_existing_revision" && before == [DistributionCatalogRevision, DistributionCatalogBoolean, DistributionCatalogPort, DistributionCatalogImport, CatalogManagement, CatalogManagementChange].map(&:count)
client.post("/api/v1/catalogs/import-confirm", params: bytes, headers: { "CONTENT_TYPE" => "application/octet-stream", "X-CSRF-Token" => client.response.headers["X-CSRF-Token"], "X-Catalog-Preview" => preview.fetch("preview_token") })
confirmation = JSON.parse(client.response.body)
raise "Browser duplicate failed" unless client.response.status == 200 && confirmation["outcome"] == "reuse_existing_revision" && confirmation.dig("catalog", "content_digest") == artifact.content_digest
raise "Old disposable import rewritten" unless revision.reload.attributes == original_revision && revision.distribution_catalog_imports.first.reload.attributes == original_import
raise "Browser bytes differ" unless DistributionCatalogImport.find(confirmation.dig("catalog_import", "id")).artifact == bytes
raise "Duplicate changed lifecycle/name" unless revision.catalog_management.reload.attributes == original_management

raise "Unexpected import counts" unless DistributionCatalogRevision.count == 1 && DistributionCatalogImport.count == 2
raise "Import source kinds differ" unless revision.distribution_catalog_imports.order(:id).pluck(:source_kind) == %w[administrative_cli operator_upload]
boot_state = "[DistributionCatalogRevision.count, DistributionCatalogBoolean.count, DistributionCatalogPort.count, DistributionCatalogImport.count, CatalogManagement.count, CatalogManagementChange.count, CatalogManagement.order(:id).pluck(:display_name, :lifecycle)]"
expected = JSON.generate([DistributionCatalogRevision.count, DistributionCatalogBoolean.count, DistributionCatalogPort.count, DistributionCatalogImport.count, CatalogManagement.count, CatalogManagementChange.count, CatalogManagement.order(:id).pluck(:display_name, :lifecycle)])
output, status = Open3.capture2e("bundle", "exec", "rails", "db:prepare")
raise "Database preparation failed: #{output}" unless status.success?
output, status = Open3.capture2e("bundle", "exec", "rails", "runner", "puts JSON.generate(#{boot_state})")
raise "Startup changed catalog state: #{output}" unless status.success? && output.strip == expected
puts JSON.pretty_generate(source_path: relative, content_digest: artifact.content_digest,
  platform: artifact.catalog["platform"], policy: artifact.catalog["policy"],
  raw_sha256: Digest::SHA256.hexdigest(bytes), supported: source.supported_count, offline_copy_validated: true,
  cli_created: true, browser_reused: true, preview_pure: true, exact_bytes: true,
  revisions: DistributionCatalogRevision.count, imports: DistributionCatalogImport.count,
  startup_unchanged: true)
