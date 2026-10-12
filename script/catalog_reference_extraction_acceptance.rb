# Disposable test DB; source DB is read only. Drains the production job in a controlled test adapter.
# REFERENCE_SOURCE_DATABASE_URL=... bundle exec rails runner script/catalog_reference_extraction_acceptance.rb
raise "Use an empty disposable test database" unless Rails.env.test? && PolicyArtifact.count.zero? && DistributionCatalogRevision.count.zero?
require "pg"
require "active_job/queue_adapters/test_adapter"
ActiveJob::Base.queue_adapter = :test

CatalogDistributionSource.verify(Rails.root.join("catalogs"))
path = Rails.root.join("catalogs").glob("**/*.review.json").sort.first.sub_ext("").sub_ext(".json")
json = DistributionCatalogArtifact.read(path).validate!
identity = json.catalog.dig("policy", "loaded_policy_digest")
source = PG.connect(ENV.fetch("REFERENCE_SOURCE_DATABASE_URL"))
source.exec("BEGIN READ ONLY")
row = source.exec_params("SELECT id, artifact, source_host_id, permissive_domain_analysis FROM policy_artifacts WHERE policy_identity = $1", [identity]).first
raise "Exact retained companion is unavailable" unless row
bytes = PG::Connection.unescape_bytea(row.fetch("artifact"))
prior = JSON.parse(row.fetch("permissive_domain_analysis"))
source.exec("ROLLBACK")
source.close
PolicyArtifact.validate_bytes!(identity, bytes)

# Existing host-side consumer and job establish the new-version cache on real bytes.
policy = PolicyArtifact.store!(policy_identity: identity, bytes: bytes, source_host_id: row["source_host_id"], defer_analysis: true)
state = PolicyPermissiveDomains.lookup(identity)
raise "First host-side read was not asynchronous pending" unless state[:status] == "pending" && state[:domains].nil?
raise "No job requested" unless ActiveJob::Base.queue_adapter.enqueued_jobs.one?
started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
AnalyzePolicyPermissiveDomainsJob.perform_now(policy.id, PolicyPermissiveDomainAnalyzer::SEMANTICS_VERSION)
runtime = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
host_result = PolicyPermissiveDomains.lookup(identity)
raise "Real extraction failed: #{host_result.inspect}" unless host_result[:status] == "observed"
raise "Noncanonical extracted set" unless host_result[:domains] == host_result[:domains].uniq.sort
raise "Prior host semantics disagree" if prior["status"] == "observed" && prior["domains"] != host_result[:domains]

revision = ImportDistributionCatalog.call(artifact: json, source_kind: "administrative_cli").revision
original_import = revision.distribution_catalog_imports.first.attributes
original_revision = revision.attributes
AttachCatalogPolicy.call(revision: revision, bytes: bytes, acquisition_basis: "Offline retained exact reference-system artifact")
jobs = ActiveJob::Base.queue_adapter.enqueued_jobs.size
evaluated_at = policy.reload.permissive_domain_analysis.fetch("evaluated_at")
result = revision.reference_permissive_domains
raise "Reference did not reuse exact host cache" unless result[:status] == "observed" && result[:domains] == host_result[:domains] && result[:evaluated_at] == evaluated_at
raise "Reference caused duplicate parse/job" unless jobs == ActiveJob::Base.queue_adapter.enqueued_jobs.size && policy.reload.permissive_domain_analysis["evaluated_at"] == evaluated_at
revision.catalog_management.change!(lifecycle: "archived", changed_by: "acceptance")
raise "Archive lost derived facts" unless revision.reference_permissive_domains[:domains] == result[:domains]
revision.catalog_management.change!(lifecycle: "active", changed_by: "acceptance")
raise "Catalog semantic/import evidence changed" unless revision.reload.attributes == original_revision && revision.distribution_catalog_imports.first.reload.attributes == original_import
raise "Host evidence fabricated" unless [Host, HostSnapshot, RawEvent].all? { |model| model.count.zero? }
raise "Future family enabled" unless CatalogReferenceSelection.for_policy_identity(identity).family("effective_permissive_domains")[:status] == "unsupported"

cache_started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
20.times { PolicyPermissiveDomains.lookup(identity) }
cached_ms = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - cache_started) * 1000 / 20
puts JSON.pretty_generate(content_digest: revision.content_digest, reference_policy_sha: identity,
  policy_bytes: bytes.bytesize, status: result[:status], domains: result[:domains], count: result[:domains].length,
  evaluator_version: result[:evaluator_version], semantics_version: result[:semantics_version], runtime_seconds: runtime,
  cached_lookup_mean_ms: cached_ms, wall_limit_seconds: 30, cpu_limit_seconds: 30,
  address_space_limit_bytes: 512 * 1024 * 1024, combined_output_limit_bytes: SetoolsProcess::MAX_OUTPUT,
  prior_host_cache_crosscheck: prior["status"] == "observed", reference_reused_current_host_cache: true,
  no_duplicate_job: true, no_host_fabrication: true, archive_retained: true, v3_and_import_unchanged: true)
