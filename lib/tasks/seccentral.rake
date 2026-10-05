require "json"
require "digest"

DEMO_HOST_PERSONAS = [
  { id: "rhel9-web-01", os_id: "rhel", os_version: "9.4", enforcement: "enforcing", agent_version: "demo-0.2.0", policy_identity: "rhel9-web", liveness: :reporting, scenarios: ["scenario-001-file-context-mismatch", "scenario-002-network-connect"] },
  { id: "rhel8-web-02", os_id: "rhel", os_version: "8.9", enforcement: "enforcing", agent_version: "demo-0.1.0", policy_identity: "rhel8-web", liveness: :reporting, scenarios: ["scenario-003-port-bind", "scenario-002b-network-connect-no-match"] },
  { id: "rhel8-db-01", os_id: "rhel", os_version: "8.10", enforcement: "enforcing", agent_version: "demo-0.1.0", policy_identity: "rhel9-web", liveness: :stale, scenarios: ["scenario-004-relocated-mariadb"] },
  { id: "rhel9-web-02", os_id: "rhel", os_version: "9.5", enforcement: "permissive", agent_version: "demo-0.2.0", policy_identity: "rhel9-web", liveness: :reporting, scenarios: ["scenario-002-network-connect"] },
  { id: "rhel9-web-03", os_id: "rhel", os_version: "9.6", enforcement: "enforcing", agent_version: "demo-0.2.0", policy_identity: "rhel9-web-custom", liveness: :reporting, scenarios: [] },
  { id: "rhel9-db-01", os_id: "rhel", os_version: "9.4", enforcement: "enforcing", agent_version: "demo-0.2.0", policy_identity: "alma9-db", liveness: :reporting, scenarios: ["scenario-004-relocated-mariadb"] },
  { id: "rhel8-web-01", os_id: "rhel", os_version: "8.10", enforcement: "enforcing", agent_version: "demo-0.1.0", policy_identity: "rhel8-web", liveness: :reporting, scenarios: ["scenario-003-port-bind"] },
  { id: "alma8-web-01", os_id: "almalinux", os_version: "8.10", enforcement: "enforcing", agent_version: "demo-0.1.0", policy_identity: "rhel8-web", liveness: :reporting, scenarios: ["scenario-003-port-bind"] },
  { id: "alma9-web-01", os_id: "almalinux", os_version: "9.3", enforcement: "enforcing", agent_version: "demo-0.2.0", policy_identity: "alma9-web", liveness: :reporting, scenarios: ["systemd-nsresource-read"] },
  { id: "alma9-db-01", os_id: "almalinux", os_version: "9.3", enforcement: "enforcing", agent_version: "demo-0.2.0", policy_identity: "alma9-db", liveness: :offline, scenarios: ["scenario-004-relocated-mariadb"] },
  { id: "alma10-web-01", os_id: "almalinux", os_version: "10.0", enforcement: "enforcing", agent_version: "demo-0.2.0", policy_identity: "rhel10-web", liveness: :reporting, scenarios: ["scenario-005-execute"] },
  { id: "rocky8-web-01", os_id: "rocky", os_version: "8.10", enforcement: "enforcing", agent_version: "demo-0.1.0", policy_identity: "rhel8-web", liveness: :reporting, scenarios: ["scenario-003-port-bind"] },
  { id: "rocky9-web-01", os_id: "rocky", os_version: "9.5", enforcement: "enforcing", agent_version: "demo-0.2.0", policy_identity: "rhel9-web", liveness: :reporting, scenarios: ["scenario-002-network-connect"] },
  { id: "rocky10-web-01", os_id: "rocky", os_version: "10.0", enforcement: "enforcing", agent_version: "demo-0.2.0", policy_identity: "rhel10-web", liveness: :reporting, scenarios: ["scenario-005-execute"] },
  { id: "fedora40-workstation", os_id: "fedora", os_version: "40", enforcement: "enforcing", agent_version: "demo-0.1.0", policy_identity: "fedora40", liveness: :reporting, scenarios: ["systemd-nsresource-read"] },
  { id: "fedora41-workstation", os_id: "fedora", os_version: "41", enforcement: "enforcing", agent_version: "demo-0.2.0", policy_identity: "fedora41", liveness: :reporting, scenarios: ["systemd-nsresource-lock", "container-postgresql-backup-file"] },
  { id: "rhel10-web-01", os_id: "rhel", os_version: "10.0", enforcement: "enforcing", agent_version: "demo-0.2.0", policy_identity: "rhel10-web", liveness: :reporting, scenarios: ["scenario-005-execute"] },
  { id: "alma10-recovered-01", os_id: "almalinux", os_version: "10.0", enforcement: "disabled", agent_version: "demo-0.2.0", policy_identity: "rhel9-web", liveness: :reporting, scenarios: [] },
  { id: "rocky9-quiet-01", os_id: "rocky", os_version: "9.5", enforcement: "enforcing", agent_version: "demo-0.2.0", policy_identity: "rocky9-quiet", liveness: :offline, scenarios: [] }
].freeze

namespace :secentral do

  namespace :catalog do
    task :validate, [:file] => :environment do |_, args|
      abort "secentral:catalog:validate requires FILE" unless args[:file]

      artifact = DistributionCatalogArtifact.read(args[:file]).validate!
      puts "Valid: #{artifact.content_digest} #{artifact.catalog.dig("policy", "loaded_policy_digest")}"
    rescue DistributionCatalogArtifact::Invalid => error
      abort "Invalid catalog: #{error.message}"
    end

    # Import a distribution catalog JSON file (expects full artifact format with metadata).
    # Usage: bundle exec rake secentral:catalog:import[/path/to/catalog.json]
    task :import, [:file] => :environment do |_, args|
      abort "secentral:catalog:import requires FILE" unless args[:file]

      result = ImportDistributionCatalog.call(
        artifact: DistributionCatalogArtifact.read(args[:file]),
        source_path: args[:file]
      )
      revision = result.revision
      puts "#{result.created ? "Imported" : "Reused"}: #{revision.content_digest} #{revision.loaded_policy_digest} #{revision.distribution} #{revision.major_version} #{revision.policy_type}; booleans=#{revision.distribution_catalog_booleans.count} ports=#{revision.distribution_catalog_ports.count} import=#{result.catalog_import.id}"
    rescue DistributionCatalogArtifact::Invalid, ImportDistributionCatalog::Conflict => error
      abort "Catalog import failed: #{error.message}"
    end
  end

  namespace :demo do
    task reset: :environment do
      abort "secentral:demo:reset is disabled in production" if Rails.env.production?

      organization = Organization.find_by(name: "SECentral Demo")
      if organization
        ActiveRecord::Base.transaction do
          raw_event_ids = organization.raw_events.select(:id)
          host_ids = organization.hosts.select(:id)
          Occurrence.where(organization_id: organization.id).destroy_all
          NormalizedDenial.where(raw_event_id: raw_event_ids).delete_all
          RawAuditRecord.where(raw_event_id: raw_event_ids).delete_all
          RawEvent.where(organization_id: organization.id).delete_all
          HostSnapshotObservation.where(host_id: host_ids).delete_all
          HostSnapshot.where(host_id: host_ids).delete_all
          IssueDispositionChange.where(issue_id: organization.issues.select(:id)).delete_all
          Issue.where(organization_id: organization.id).delete_all
          AgentInstallation.where(organization_id: organization.id).delete_all
          Host.where(organization_id: organization.id).delete_all
          organization.delete
        end
        puts "Removed SECentral Demo"
      else
        puts "SECentral Demo does not exist"
      end
    end
  end

  task demo: :environment do
    abort "secentral:demo is disabled in production" if Rails.env.production?

    Rake::Task["secentral:demo:reset"].invoke
    organization = Organization.create!(name: "SECentral Demo")
    fixtures = JSON.parse(File.read(Rails.root.join("spec/fixtures/demo/avcs.json")))
    base_time = Time.current.change(usec: 0)
    hosts = demo_hosts(organization, base_time)

    fixtures_by_id = fixtures.index_by { |fixture| fixture.fetch("id") }
    DEMO_HOST_PERSONAS.each_with_index do |persona, host_index|
      persona.fetch(:scenarios).each_with_index do |scenario, scenario_index|
        fixture = fixtures_by_id.fetch(scenario)
        ingest_demo_event(hosts.fetch(host_index), fixture, base_time + (host_index + scenario_index + 1).hours)
      end
    end

    issues = organization.issues.order(:id).to_a
    if issues[0]
      issues[0].transition_to!("resolved")
      ingest_demo_event(hosts.first, fixtures.first, base_time + 30.days)
    end
    if issues[1]
      issues[1].transition_to!("ignored")
      ingest_demo_event(hosts.last, fixtures[1], base_time + 31.days)
    end

    set_demo_reporting_states(hosts)

    puts "Created SECentral Demo: #{organization.hosts.count} hosts, #{organization.issues.count} issues, #{organization.occurrences.count} occurrences"
  end

  task reprocess: :environment do
    RawEvent.find_each do |raw_event|
      AvcNormalizer.call(raw_event.raw_audit_records.to_a).each_with_index do |result, ordinal|
        PersistNormalizedDenial.call(raw_event, result, ordinal: ordinal, normalization_version: ProcessRawEvent::NORMALIZATION_VERSION)
      end
    end
    puts "Reprocessed #{RawEvent.count} raw events"
  end

  def demo_hosts(organization, base_time)
    DEMO_HOST_PERSONAS.each_with_index.map do |persona, index|
      external_id = persona.fetch(:id)
      platform = persona.fetch(:os_id)
      version = persona.fetch(:os_version)
      enforcement = persona.fetch(:enforcement)
      agent_version = persona.fetch(:agent_version)
      policy_label = persona.fetch(:policy_identity)
      policy_identity = "sha256:#{Digest::SHA256.hexdigest(policy_label)}"
      kernel_policy_version = case version.to_s
      when /\A8/ then 31
      when /\A9/ then 34
      else 35
      end
      liveness = persona.fetch(:liveness)
      custom_module = policy_label.include?("custom")
      boolean_status = "observed"
      booleans = [
        { "name" => "httpd_can_network_connect", "current" => false, "default" => false, "status" => "observed" },
        { "name" => "nis_enabled", "current" => false, "default" => false, "status" => "observed" },
        { "name" => "httpd_enable_cgi", "current" => true, "default" => true, "status" => "observed" },
        { "name" => "httpd_unified", "current" => false, "default" => false, "status" => "observed" },
        { "name" => "httpd_builtin_scripting", "current" => true, "default" => true, "status" => "observed" }
      ]
      if external_id == "rhel9-web-02"
        booleans.first["current"] = true
      elsif external_id == "rhel8-db-01"
        booleans.first["current"] = true
      elsif external_id == "rocky9-web-01"
        booleans = [{ "name" => "httpd_can_network_connect", "current" => false, "default" => nil, "status" => "unknown" }]
      elsif external_id == "alma10-recovered-01"
        boolean_status = "unavailable"
        booleans = []
      elsif external_id == "rocky9-quiet-01"
        booleans = [{ "name" => "httpd_can_network_connect", "current" => false, "default" => nil, "status" => "unknown" }]
      end
      port_inventory = {
        "status" => "observed", "local_classification_status" => "observed",
        "mappings" => [
          { "type" => "unreserved_port_t", "protocol" => "tcp", "ports" => [{ "start" => 12345, "end" => 12345, "provenance" => "not_confirmed_custom" }] },
          { "type" => "http_port_t", "protocol" => "tcp", "ports" => [{ "start" => 80, "end" => 80, "provenance" => "not_confirmed_custom" }, { "start" => 443, "end" => 443, "provenance" => "not_confirmed_custom" }] }
        ]
      }
      case external_id
      when "rhel9-web-01"
        port_inventory["mappings"] = [
          { "type" => "http_port_t", "protocol" => "tcp", "ports" => [{ "start" => 80, "end" => 85, "provenance" => "not_confirmed_custom" }, { "start" => 86, "end" => 90, "provenance" => "not_confirmed_custom" }] },
          { "type" => "unreserved_port_t", "protocol" => "tcp", "ports" => [{ "start" => 12345, "end" => 12345, "provenance" => "not_confirmed_custom" }] }
        ]
      when "rhel9-web-02"
        port_inventory["mappings"] = []
      when "rhel8-web-02"
        port_inventory = { "status" => "unavailable", "local_classification_status" => "unavailable", "mappings" => [] }
      when "rhel8-web-01"
        port_inventory["status"] = "partial"
      when "rhel9-web-03"
        port_inventory["local_classification_status"] = "unavailable"
        port_inventory["mappings"].each { |mapping| mapping["ports"].each { |range| range["provenance"] = "unknown" } }
      when "alma8-web-01"
        port_inventory["local_classification_status"] = "partial"
        port_inventory["mappings"].first["ports"].first["provenance"] = "custom"
        port_inventory["mappings"].last["ports"].each { |range| range["provenance"] = "unknown" }
      when "rocky9-web-01"
        port_inventory["mappings"] = [
          { "type" => "my_app_port_t", "protocol" => "tcp", "ports" => [{ "start" => 80, "end" => 90, "provenance" => "custom" }] },
          { "type" => "unreserved_port_t", "protocol" => "tcp", "ports" => [{ "start" => 12345, "end" => 12345, "provenance" => "not_confirmed_custom" }] }
        ]
      when "alma10-recovered-01"
        port_inventory = { "status" => "unknown", "local_classification_status" => "unknown", "mappings" => [] }
      end
      details = {
        "id" => external_id,
        "hostname" => "#{external_id}.demo.secentral",
        "boot_id" => "demo-boot-#{index + 1}",
        "selinux" => {
          "enabled" => enforcement != "disabled",
          "enforcement" => enforcement,
          "policy_identity" => policy_identity,
          "kernel_policy_version" => kernel_policy_version,
          "boolean_status" => boolean_status,
          "booleans" => booleans,
          "policy" => {
            "identity" => policy_label,
            "package" => "selinux-policy-#{version}",
            "modules" => [
              { "name" => "httpd", "priority" => 200, "provenance" => "distribution", "source_package" => "httpd" }
            ] + (custom_module ? [{ "name" => "local_web", "priority" => 400, "provenance" => "custom" }] : []),
            "port_inventory" => port_inventory,
            "file_contexts" => custom_module ? [
              { "pattern" => "/srv/www(/.*)?", "file_type" => "all files", "context" => "httpd_sys_content_t", "provenance" => "custom" }
            ] : []
          }
        },
        "platform" => { "os_id" => platform, "os_version" => version }
      }
      host = organization.hosts.create!(
        external_id: details["id"], hostname: details["hostname"],
        boot_id: details["boot_id"], last_seen_at: liveness_timestamp(liveness, base_time)
      )
      snapshot = host.host_snapshots.create!(details: details)
      installation = organization.agent_installations.create!(name: "demo-agent-#{index + 1}", agent_version: agent_version, last_seen_at: liveness_timestamp(liveness, base_time))
      installation.update!(bound_host: host)
      heartbeat_at = liveness_timestamp(liveness, base_time)
      host.host_snapshot_observations.create!(host_snapshot: snapshot, agent_installation: installation, first_observed_at: heartbeat_at, last_observed_at: heartbeat_at, first_received_at: heartbeat_at, last_received_at: heartbeat_at) if heartbeat_at
      host
    end
  end

  def ingest_demo_event(host, fixture, timestamp)
    payload = {
      "schema_version" => 4,
      "agent" => { "version" => fixture.fetch("agent_version", host.agent_installations.first.agent_version) },
      "host_id" => host.external_id,
      "boot_id" => host.boot_id,
      "host_observed_at" => (host.current_state_observation&.last_observed_at || timestamp).iso8601(6),
      "events" => [ {
        "category" => "avc",
        "audit_event" => { "timestamp" => timestamp.iso8601(6), "sequence" => timestamp.to_i },
        "agent_received_at" => timestamp.iso8601(6),
        "completion_reason" => "eoe",
        "records" => ([fixture] + Array(fixture["records"])).each_with_index.map do |record, position|
          { "position" => position, "type" => record.fetch("type", "avc"), "type_name" => record.fetch("type_name", record.fetch("type", "avc").upcase), "timestamp" => timestamp.iso8601(6), "sequence" => timestamp.to_i, "payload" => [record.fetch("payload")].pack("m0") }
        end,
      } ]
    }
    IngestEvents.new(organization: host.organization, payload: payload).call.each { |event| ProcessRawEvent.call(event) }
  end

  def liveness_timestamp(state, now)
      { reporting: now - 2.minutes, stale: now - 30.minutes, offline: now - 2.hours }.fetch(state)
  end

  def set_demo_reporting_states(hosts)
    now = Time.current.change(usec: 0)
    hosts.each_with_index do |host, index|
      timestamp = liveness_timestamp(DEMO_HOST_PERSONAS.fetch(index).fetch(:liveness), now)
      host.agent_installations.first.update!(last_seen_at: timestamp)
      host.update!(last_seen_at: timestamp)
    end
  end

end
