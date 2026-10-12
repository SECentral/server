# Disposable test DB. Replays unchanged retained host observations, never fabricates checkpoints.
# REFERENCE_SOURCE_DATABASE_URL=... bundle exec rails runner script/effective_permissive_comparison_acceptance.rb
raise "Use an empty disposable test database" unless Rails.env.test? && Host.count.zero? && DistributionCatalogRevision.count.zero?
Organization.delete_all # Remove only the disposable database's default seed before unchanged replay.
require "pg"
require "action_dispatch/testing/integration"
require "active_support/testing/time_helpers"
extend ActiveSupport::Testing::TimeHelpers
ActiveJob::Base.queue_adapter = :test
source = PG.connect(ENV.fetch("REFERENCE_SOURCE_DATABASE_URL"))
source.exec("BEGIN READ ONLY")

def copy_row(source, model, id)
  return model.find(id) if model.exists?(id)

  row = JSON.parse(source.exec_params("SELECT row_to_json(t) AS record FROM #{model.table_name} t WHERE id = $1", [id]).first.fetch("record"))
  model.create!(row)
end

def retained_host(source, observation_id)
  row = JSON.parse(source.exec_params("SELECT row_to_json(t) AS record FROM host_snapshot_observations t WHERE id = $1", [observation_id]).first.fetch("record"))
  host_row = JSON.parse(source.exec_params("SELECT row_to_json(t) AS record FROM hosts t WHERE id = $1", [row.fetch("host_id")]).first.fetch("record"))
  copy_row(source, Organization, host_row.fetch("organization_id"))
  host = copy_row(source, Host, host_row.fetch("id"))
  copy_row(source, AgentInstallation, row.fetch("agent_installation_id"))
  snapshot = copy_row(source, HostSnapshot, row.fetch("host_snapshot_id"))
  observation = copy_row(source, HostSnapshotObservation, observation_id)
  # This controlled replay contains evidence available at the retained observation,
  # not today's later checkpoints/transitions. Reject a masked observation window.
  boundaries = source.exec_params("SELECT count(*) FROM raw_events WHERE host_id=$1 AND boot_id=$2 AND audit_timestamp >= $3 AND audit_timestamp <= $4 AND (transition_type IS NOT NULL OR checkpoint_invalidated_fields <> '[]'::jsonb)",
    [host.id, snapshot.details["boot_id"], row["last_observed_at"], row["last_received_at"]]).first.fetch("count").to_i
  raise "Retained observation crosses a known identity boundary" unless boundaries.zero?
  [host, observation]
end

catalog_path = Rails.root.join("catalogs").glob("**/*.review.json").sort.first.sub_ext("").sub_ext(".json")
json = DistributionCatalogArtifact.read(catalog_path).validate!
reference_identity = json.catalog.dig("policy", "loaded_policy_digest")
exact_host, exact_observation = retained_host(source, 892)
different_host, different_observation = retained_host(source, 931)
raise "Exact retained input differs" unless exact_host.current_policy_identity == reference_identity
identities = [reference_identity, different_host.current_policy_identity]
identities.each do |identity|
  row = source.exec_params("SELECT artifact, source_host_id FROM policy_artifacts WHERE policy_identity=$1", [identity]).first
  policy = PolicyArtifact.store!(policy_identity: identity, bytes: PG::Connection.unescape_bytea(row.fetch("artifact")), source_host_id: row["source_host_id"], defer_analysis: true)
  PolicyPermissiveDomains.lookup(identity)
  AnalyzePolicyPermissiveDomainsJob.perform_now(policy.id, PolicyPermissiveDomainAnalyzer::SEMANTICS_VERSION)
  raise "Real extraction unavailable" unless PolicyPermissiveDomains.lookup(identity)[:status] == "observed"
end
source.exec("ROLLBACK")
source.close

revision = ImportDistributionCatalog.call(artifact: json, source_kind: "administrative_cli").revision
AttachCatalogPolicy.call(revision: revision, bytes: PolicyArtifact.find_by!(policy_identity: reference_identity).artifact,
  acquisition_basis: "Offline retained exact reference policy")
original_snapshots = [exact_host, different_host].map { |host| host.current_snapshot.attributes }
original_revision = revision.attributes
ENV["ADMIN_USERNAME"] = "comparison-acceptance"
ENV["ADMIN_PASSWORD_DIGEST"] = BCrypt::Password.create("acceptance-only").to_s
Api::V1::BaseController.config.allow_forgery_protection = true
client = ActionDispatch::Integration::Session.new(Rails.application)
client.get("/api/v1/sessions")
client.post("/api/v1/sessions", params: { username: "comparison-acceptance", password: "acceptance-only" }, headers: { "X-CSRF-Token" => client.response.headers["X-CSRF-Token"] })
raise "Login failed" unless client.response.status == 201

results = {}
enqueued_before_requests = ActiveJob::Base.queue_adapter.enqueued_jobs.size
[["exact", exact_host, exact_observation, nil], ["explicit", different_host, different_observation, revision.id], ["fallback_refused", different_host, different_observation, nil]].each do |name, host, observation, chosen|
  travel_to(observation.last_received_at + 1.second) do
    client.get("/api/v1/hosts/#{host.id}/configuration", params: chosen ? { reference_revision_id: chosen } : {})
    raise "Configuration API failed" unless client.response.status == 200
    result = JSON.parse(client.response.body).dig("comparison", "effective_permissive_domains")
    results[name] = result
    if name == "exact"
      raise "Exact result incorrect" unless result["status"] == "observed" && result["counts"] == { "matching" => 7, "unexpected_on_host" => 0, "missing_from_host" => 0 } && result.dig("selection", "basis") == "exact_policy_identity"
    elsif name == "explicit"
      raise "Explicit difference incorrect" unless result["unexpected_on_host"] == ["postgresql_t"] && result["missing_from_host"] == [] && result.dig("selection", "equivalence_asserted") == false
    else
      raise "Fallback acquired effective authority" unless result["reason"] == "effective_policy_requires_exact_reference" && result["matching"].nil?
    end
  end
end

queries = []
subscriber = ActiveSupport::Notifications.subscribe("sql.active_record") { |*, payload| queries << payload[:sql] if payload[:sql].start_with?("SELECT") }
started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
travel_to(exact_observation.last_received_at + 1.second) { HostConfigurationQuery.call(exact_host) }
elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000
ActiveSupport::Notifications.unsubscribe(subscriber)
family_ms = travel_to(exact_observation.last_received_at + 1.second) do
  comparison = HostConfigurationComparison.call(exact_host)
  started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  10.times { comparison.send(:compare_effective_permissive_domains) }
  (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000 / 10
end
raise "Evidence mutated" unless original_snapshots == [exact_host, different_host].map { |host| host.current_snapshot.reload.attributes } && revision.reload.attributes == original_revision
raise "Synthetic raw events created" unless RawEvent.count.zero?
raise "Unrequested extra host observations" unless HostSnapshotObservation.count == 2
raise "Request triggered extraction" unless ActiveJob::Base.queue_adapter.enqueued_jobs.size == enqueued_before_requests
puts JSON.pretty_generate(results: results, retained_snapshot_ids: [exact_host.current_snapshot.id, different_host.current_snapshot.id],
  as_of_observation_ids: [exact_observation.id, different_observation.id], cached_configuration_selects: queries.size, cached_configuration_ms: elapsed,
  policy_metadata_queries: queries.count { |sql| sql.include?("CASE WHEN artifact_size") },
  cached_effective_family_mean_ms: family_ms,
  replay_scope: "Unchanged retained observations evaluated in controlled disposable as-of context; not persisted historical comparison", v3_unchanged: true)
