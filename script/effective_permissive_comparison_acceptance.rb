# JSON-only V4 reference acceptance against an unchanged retained host observation.
# Run in an empty disposable test DB with REFERENCE_SOURCE_DATABASE_URL set.
# Example: bundle exec rails runner script/effective_permissive_comparison_acceptance.rb
begin
raise "Use an empty disposable test database" unless Rails.env.test? &&
  Host.count.zero? && DistributionCatalogRevision.count.zero? && PolicyArtifact.count.zero?

require "pg"
require "action_dispatch/testing/integration"
require "active_support/testing/time_helpers"
extend ActiveSupport::Testing::TimeHelpers
ActiveJob::Base.queue_adapter = :test

source = PG.connect(ENV.fetch("REFERENCE_SOURCE_DATABASE_URL"))
source.exec("BEGIN READ ONLY")

def source_row(source, table, id)
  JSON.parse(source.exec_params("SELECT row_to_json(t) AS record FROM #{table} t WHERE id = $1", [id]).first.fetch("record"))
end

def copy_row(source, model, id)
  return model.find(id) if model.exists?(id)

  model.create!(source_row(source, model.table_name, id))
end

def import_with_preview(client, bytes)
  counts = [DistributionCatalogRevision, DistributionCatalogImport, CatalogManagement, CatalogManagementChange].map(&:count)
  client.post("/api/v1/catalogs/import-preview", params: bytes,
    headers: { "CONTENT_TYPE" => "application/octet-stream", "X-CSRF-Token" => client.response.headers["X-CSRF-Token"] })
  raise "V4 preview failed: #{client.response.status} #{client.response.body}" unless client.response.status == 200
  token = JSON.parse(client.response.body).dig("preview", "preview_token")
  raise "V4 preview mutated catalog state" unless counts == [DistributionCatalogRevision, DistributionCatalogImport, CatalogManagement, CatalogManagementChange].map(&:count)

  client.post("/api/v1/catalogs/import-confirm", params: bytes,
    headers: { "CONTENT_TYPE" => "application/octet-stream", "X-CSRF-Token" => client.response.headers["X-CSRF-Token"], "X-Catalog-Preview" => token })
  raise "V4 confirmation failed: #{client.response.status} #{client.response.body}" unless [200, 201].include?(client.response.status)

  JSON.parse(client.response.body)
end

host_id = Integer(ENV.fetch("REFERENCE_HOST_ID", "1138"))
host_row = source_row(source, "hosts", host_id)
observation_row = JSON.parse(source.exec_params(
  "SELECT row_to_json(t) AS record FROM host_snapshot_observations t WHERE host_id = $1 ORDER BY last_received_at DESC, id DESC LIMIT 1", [host_id]
).first.fetch("record"))
copy_row(source, Organization, host_row.fetch("organization_id"))
host = copy_row(source, Host, host_id)
copy_row(source, AgentInstallation, observation_row.fetch("agent_installation_id"))
snapshot = copy_row(source, HostSnapshot, observation_row.fetch("host_snapshot_id"))
observation = copy_row(source, HostSnapshotObservation, observation_row.fetch("id"))
identity = snapshot.details.dig("selinux", "policy_identity")
raise "Retained host observation has no valid policy identity" unless identity.to_s.match?(PolicyArtifact::IDENTITY_FORMAT)

# Preserve the existing V3 AlmaLinux catalog as the pre-import state so this
# acceptance also records how a new V4 AlmaLinux catalog coexists with it.
old_catalog = JSON.parse(source.exec_params(
  "SELECT row_to_json(t) AS record FROM distribution_catalog_revisions t WHERE distribution = $1 AND major_version = $2 AND collector_semantics_version = 3 ORDER BY id LIMIT 1",
  ["almalinux", "9"]
).first.fetch("record"))
old_attributes = old_catalog.slice(*DistributionCatalogRevision.attribute_names).except("id", "created_at", "updated_at")
old_revision = DistributionCatalogRevision.create!(old_attributes.merge(initial_display_name: "AlmaLinux 9 (existing V3)"))
old_booleans = source.exec_params("SELECT name, default_value, description FROM distribution_catalog_booleans WHERE distribution_catalog_revision_id = $1 ORDER BY name", [old_catalog.fetch("id")])
old_booleans.each do |entry|
  old_revision.distribution_catalog_booleans.create!(name: entry["name"], default_value: entry["default_value"] == "t", description: entry["description"])
end
old_ports = source.exec_params("SELECT protocol, start_port, end_port, selinux_type FROM distribution_catalog_ports WHERE distribution_catalog_revision_id = $1 ORDER BY protocol, start_port, end_port, selinux_type", [old_catalog.fetch("id")])
old_ports.each do |mapping|
  old_revision.distribution_catalog_ports.create!(protocol: mapping["protocol"], start_port: mapping["start_port"], end_port: mapping["end_port"], selinux_type: mapping["selinux_type"])
end
old_immutable = [old_revision.attributes, old_revision.distribution_catalog_booleans.map(&:attributes), old_revision.distribution_catalog_ports.map(&:attributes)]

policy_row = source.exec_params(
  "SELECT artifact, source_host_id, permissive_domain_analysis FROM policy_artifacts WHERE policy_identity = $1", [identity]
).first
raise "Host exact policy artifact is not retained" unless policy_row
policy_bytes = PG::Connection.unescape_bytea(policy_row.fetch("artifact"))
analysis = JSON.parse(policy_row.fetch("permissive_domain_analysis"))
raise "Host permissive analysis is not current/observed" unless analysis["status"] == "observed" && analysis["semantics_version"] == PolicyPermissiveDomainAnalyzer::SEMANTICS_VERSION
policy = PolicyArtifact.store!(policy_identity: identity, bytes: policy_bytes, source_host_id: policy_row["source_host_id"], defer_analysis: true)
policy.update_column(:permissive_domain_analysis, analysis)

source.exec("ROLLBACK")
source.close

catalog_path = ARGV.first || Rails.root.join("catalogs/almalinux/9/targeted/d20d808874f15504d1dc7f2783d6d7320a269043d0c007333423580596fb1a08.json")
artifact = DistributionCatalogArtifact.read(catalog_path).validate!
raise "Expected a V4 AlmaLinux 9 catalog" unless artifact.catalog.dig("platform", "distribution") == "almalinux" &&
  artifact.catalog.dig("platform", "major_version") == "9" && artifact.catalog.fetch("collector_semantics_version") == 4

ENV["ADMIN_USERNAME"] = "inline-catalog-acceptance"
ENV["ADMIN_PASSWORD_DIGEST"] = BCrypt::Password.create("acceptance-only").to_s
Api::V1::BaseController.config.allow_forgery_protection = true
client = ActionDispatch::Integration::Session.new(Rails.application)
client.get("/api/v1/sessions")
client.post("/api/v1/sessions", params: { username: "inline-catalog-acceptance", password: "acceptance-only" }, headers: { "X-CSRF-Token" => client.response.headers["X-CSRF-Token"] })
raise "Login failed" unless client.response.status == 201

first = import_with_preview(client, artifact.artifact)
new_revision = DistributionCatalogRevision.find(first.dig("catalog", "id"))
duplicate = import_with_preview(client, artifact.artifact)
raise "New policy SHA was not imported as a new revision" unless first["outcome"] == "create_new_revision" && new_revision.loaded_policy_digest != old_revision.loaded_policy_digest
raise "Same V4 content did not reuse its revision" unless duplicate["outcome"] == "reuse_existing_revision" && duplicate.dig("catalog", "id") == new_revision.id
raise "V3 revision was unexpectedly rewritten" unless old_immutable == [old_revision.reload.attributes, old_revision.distribution_catalog_booleans.reload.map(&:attributes), old_revision.distribution_catalog_ports.reload.map(&:attributes)]
raise "V4 reference unexpectedly requires a companion" if new_revision.catalog_policy_artifact
import_comparison_report = first.dig("catalog_import", "comparison_report")
raise "Semantics mismatch should not be treated as an import-time family diff" unless import_comparison_report["status"] == "none" && import_comparison_report["reason"] == "no_comparable_revision"

automatic = CatalogReferenceSelection.call(snapshot: host.current_snapshot)
raise "Both active semantics revisions should expose their incompatible family selection" unless automatic.status == "ambiguous" && automatic.reason == "incompatible_candidate_families"
lifecycle_before_archive = old_revision.catalog_management.lifecycle
old_revision.catalog_management.change!(lifecycle: "archived", changed_by: "inline-catalog-acceptance")
automatic_after_archive = CatalogReferenceSelection.call(snapshot: host.current_snapshot)
raise "Archiving the old V3 revision should leave the V4 Boolean/port fallback" unless automatic_after_archive.status == "selected" &&
  automatic_after_archive.basis == "major_release_family_agreement" &&
  automatic_after_archive.family("effective_permissive_domains")[:comparison_allowed]

jobs_before = ActiveJob::Base.queue_adapter.enqueued_jobs.size
comparison = nil
configuration_summary = nil
automatic_comparison = nil
travel_to(observation.last_received_at + 1.second) do
  client.get("/api/v1/hosts/#{host.id}/configuration")
  raise "Automatic V4 configuration request failed: #{client.response.status}" unless client.response.status == 200
  automatic_comparison = JSON.parse(client.response.body).dig("comparison", "effective_permissive_domains")
  raise "Unanimous automatic V4 reference did not compare" unless automatic_comparison["status"] == "observed" &&
    automatic_comparison.dig("selection", "basis") == "major_release_family_agreement" &&
    automatic_comparison["counts"] == { "matching" => 7, "unexpected_on_host" => 0, "missing_from_host" => 0 }

  client.get("/api/v1/hosts/#{host.id}/configuration", params: { reference_revision_id: new_revision.id })
  raise "Explicit V4 configuration request failed: #{client.response.status}" unless client.response.status == 200
  body = JSON.parse(client.response.body)
  comparison = body.fetch("comparison").fetch("effective_permissive_domains")
  configuration_summary = body.fetch("comparison").fetch("summary")
  raise "Expected retained Boolean and port differences were not displayed" unless configuration_summary.dig("booleans", "differ").positive? && configuration_summary.dig("ports", "differ").positive?
  raise "Explicit reference did not compare inline facts" unless comparison["status"] == "observed" &&
    comparison.dig("selection", "basis") == "explicit_revision" && comparison.dig("selection", "equivalence_asserted") == false
  raise "Unexpected effective permissive set comparison" unless comparison["matching"] == (analysis.fetch("domains") & artifact.catalog.dig("families", "effective_permissive_domains", "domains")).sort
  raise "Reference did not disclose inline provenance" unless comparison.dig("reference", "provenance") == "inline_catalog_extraction"
  raise "Host observed configuration comparison was not returned" unless body.dig("comparison", "summary", "booleans", "differ").to_i.positive? && body.dig("comparison", "summary", "ports", "differ").to_i.positive?
end
raise "Reference request enqueued extraction work" unless ActiveJob::Base.queue_adapter.enqueued_jobs.size == jobs_before
raise "Reference policy companion was created" if new_revision.reload.catalog_policy_artifact
raise "Reference import created a host/event observation" unless Host.count == 1 && RawEvent.count.zero? && HostSnapshotObservation.count == 1

puts JSON.pretty_generate(
  host: { id: host.id, hostname: host.hostname, observation_id: observation.id, policy_identity: identity,
    permissive_domains: analysis.fetch("domains") },
  existing_v3: { revision_id: old_revision.id, content_digest: old_revision.content_digest,
    lifecycle_before_archive: lifecycle_before_archive, lifecycle_after_archive: old_revision.catalog_management.lifecycle },
  v4_import: { created: first["outcome"] == "create_new_revision", revision_id: new_revision.id, content_digest: new_revision.content_digest,
    policy_identity: new_revision.loaded_policy_digest, duplicate_reused: duplicate["outcome"] == "reuse_existing_revision",
    import_comparison: import_comparison_report },
  automatic_selection_after_both_active: { status: automatic.status, reason: automatic.reason, basis: automatic.basis },
  automatic_selection_after_archiving_v3: { status: automatic_after_archive.status, reason: automatic_after_archive.reason, basis: automatic_after_archive.basis,
    permissive_family: automatic_after_archive.family("effective_permissive_domains") },
  automatic_v4_comparison_after_archive: automatic_comparison,
  boolean_port_comparison_summary: configuration_summary,
  explicit_v4_comparison: comparison,
  reference_companion_attached: false, extraction_jobs_enqueued_by_request: ActiveJob::Base.queue_adapter.enqueued_jobs.size - jobs_before,
  source_database_read_only: true, host_mutated: false
)
ensure
  source&.exec("ROLLBACK") rescue nil
  source&.close rescue nil
  if Rails.env.test?
    CatalogPolicyArtifact.delete_all
    DistributionCatalogImport.delete_all
    DistributionCatalogBoolean.delete_all
    DistributionCatalogPort.delete_all
    CatalogManagementChange.delete_all
    CatalogManagement.delete_all
    DistributionCatalogRevision.delete_all
    PolicyArtifact.delete_all
    HostSnapshotObservation.delete_all
    RawAuditRecord.delete_all
    RawEvent.delete_all
    HostSnapshot.delete_all
    AgentInstallation.delete_all
    Host.delete_all
    Organization.delete_all
  end
end
