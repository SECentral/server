require "rails_helper"

RSpec.describe "Configuration API", type: :request do
  let(:demo_identity) { "sha256:38ab88c50fc36df9b568ec4b7237b1693b9d0d3b64a3e9bc83f887fb9b6751f3" }

  before { sign_in_operator }

  after do
    Occurrence.delete_all
    NormalizedDenial.delete_all
    IssueDispositionChange.delete_all
    Issue.delete_all
    RawAuditRecord.delete_all
    RawEvent.delete_all
    HostSnapshotObservation.delete_all
    HostSnapshot.delete_all
    AgentInstallation.delete_all
    Host.delete_all
    Organization.delete_all
    DistributionCatalogImport.delete_all
    DistributionCatalogBoolean.delete_all
    DistributionCatalogPort.delete_all
    DistributionCatalogRevision.delete_all
  end

  def observe(host, details, at: Time.current, received_at: at)
    snapshot = HostSnapshot.create!(host: host, details: details)
    installation = host.agent_installations.first || host.organization.agent_installations.create!(name: "snapshot-agent-#{host.external_id}", bound_host: host)
    host.host_snapshot_observations.create!(agent_installation: installation, host_snapshot: snapshot, first_observed_at: at, last_observed_at: at, first_received_at: received_at, last_received_at: received_at)
    snapshot
  end

  def organization
    Organization.create!(name: "configuration-#{SecureRandom.uuid}")
  end

  def import_demo_catalog
    DistributionCatalogRevision.create!(
      schema_version: 1, content_digest: "sha256:" + "d" * 64, loaded_policy_digest: demo_identity,
      collector_semantics_version: 3, policy_type: "targeted", kernel_policy_version: 34,
      distribution: "rhel", major_version: "9", architecture: "x86_64",
      policy_packages: [], booleans_complete: true, ports_complete: true
    ).tap do |catalog|
      catalog.distribution_catalog_booleans.create!(name: "httpd_can_network_connect", default_value: false, description: "Allow HTTPD scripts and modules to connect to the network.")
      catalog.distribution_catalog_booleans.create!(name: "httpd_enable_cgi", default_value: false, description: "Allow HTTPD CGI scripts to run.")
      catalog.distribution_catalog_ports.create!(protocol: "tcp", start_port: 80, end_port: 90, selinux_type: "http_port_t")
      catalog.distribution_catalog_ports.create!(protocol: "tcp", start_port: 8080, end_port: 8080, selinux_type: "http_port_t")
    end
  end

  it "requires an operator session" do
    sign_out_operator

    get "/api/v1/configuration"

    expect(response).to have_http_status(:unauthorized)
  end

  it "rejects unknown families and malformed policy identities" do
    get "/api/v1/configuration", params: { family: "networks" }
    expect(response).to have_http_status(:unprocessable_entity)
    expect(JSON.parse(response.body)).to eq("error" => { "code" => "invalid_value", "message" => "Unknown configuration family" })

    get "/api/v1/configuration", params: { family: "booleans", policy_identity: "sha256:zzz" }
    expect(response).to have_http_status(:unprocessable_entity)
    expect(JSON.parse(response.body)).to eq("error" => { "code" => "invalid_value", "message" => "Invalid policy identity" })
  end

  it "returns host totals for the overview family" do
    org = organization
    Host.create!(organization: org, external_id: "a", hostname: "a")
    Host.create!(organization: org, external_id: "b", hostname: "b")

    get "/api/v1/configuration"

    payload = JSON.parse(response.body)
    expect(payload).to eq("family" => "overview", "families" => %w[overview booleans ports file_contexts modules], "hosts" => { "total" => 2 })
  end

  it "aggregates fleet boolean state without treating missing data as disabled" do
    org = organization
    current = Host.create!(organization: org, external_id: "current", hostname: "current", last_seen_at: Time.current)
    stale = Host.create!(organization: org, external_id: "stale", hostname: "stale", last_seen_at: Time.current)
    unavailable = Host.create!(organization: org, external_id: "unavailable", hostname: "unavailable", last_seen_at: Time.current)
    missing = Host.create!(organization: org, external_id: "missing", hostname: "missing", last_seen_at: Time.current)
    unknown = Host.create!(organization: org, external_id: "unknown", hostname: "unknown", last_seen_at: Time.current)
    named_unavailable = Host.create!(organization: org, external_id: "named-unavailable", hostname: "named-unavailable", last_seen_at: Time.current)
    observe(current, { "selinux" => { "boolean_status" => "observed", "booleans" => [{ "name" => "virt_use_nfs", "current" => true, "persistent" => false, "status" => "observed" }] } })
    observe(stale, { "selinux" => { "boolean_status" => "observed", "booleans" => [{ "name" => "virt_use_nfs", "current" => false, "persistent" => false, "status" => "observed" }] } }, at: 1.hour.ago)
    observe(unavailable, { "selinux" => { "boolean_status" => "unavailable" } })
    observe(unknown, { "selinux" => { "boolean_status" => "observed", "booleans" => [{ "name" => "virt_use_nfs", "current" => false, "status" => "unknown" }] } })
    observe(named_unavailable, { "selinux" => { "boolean_status" => "observed", "booleans" => [{ "name" => "virt_use_nfs", "current" => false, "status" => "unavailable" }] } })

    get "/api/v1/configuration", params: { family: "booleans" }

    payload = JSON.parse(response.body)
    expect(payload.fetch("family")).to eq("booleans")
    expect(payload.dig("hosts", "total")).to eq(6)
    booleans = payload.fetch("booleans")
    expect(booleans.fetch("coverage")).to eq("observed" => 1, "stale" => 1, "unavailable" => 2, "unknown" => 2)
    expect(booleans.fetch("policy_cohorts")).to be_empty
    expect(booleans.fetch("selected_policy_identity")).to be_nil
    expect(booleans.fetch("catalog")).to be_nil
    expect(booleans.fetch("catalog_overlay")).to be_nil
    expect(booleans.fetch("inventory")).to eq([{ "name" => "virt_use_nfs", "description" => nil, "counts" => { "enabled" => 1, "disabled" => 0, "unknown" => 2, "unavailable" => 2, "stale" => 1, "drift" => 1 } }])
  end

  it "keeps an all-unavailable fleet visible without named rows" do
    org = organization
    2.times do |index|
      host = Host.create!(organization: org, external_id: "unavailable-#{index}", last_seen_at: Time.current)
      observe(host, { "selinux" => { "boolean_status" => "unavailable" } })
    end

    get "/api/v1/configuration", params: { family: "booleans" }

    booleans = JSON.parse(response.body).fetch("booleans")
    expect(booleans.fetch("coverage")).to eq("unavailable" => 2, "observed" => 0, "stale" => 0, "unknown" => 0)
    expect(booleans.fetch("inventory")).to be_empty
  end

  it "aggregates an observed false boolean as disabled" do
    org = organization
    host = Host.create!(organization: org, external_id: "false-host", hostname: "false-01", last_seen_at: Time.current)
    observe(host, { "selinux" => { "booleans" => [{ "name" => "virt_use_nfs", "current" => false, "persistent" => false, "status" => "observed" }] } })

    get "/api/v1/configuration", params: { family: "booleans" }

    booleans = JSON.parse(response.body).fetch("booleans")
    expect(booleans.fetch("coverage")).to eq("observed" => 1, "unavailable" => 0, "stale" => 0, "unknown" => 0)
    expect(booleans.dig("inventory", 0, "counts")).to eq("enabled" => 0, "disabled" => 1, "unknown" => 0, "unavailable" => 0, "stale" => 0, "drift" => 0)
  end

  it "returns catalog overlays for an imported cohort" do
    catalog = import_demo_catalog
    org = organization
    host = Host.create!(organization: org, external_id: "config-host", hostname: "config-01", last_seen_at: Time.current)
    observe(host, {
      "selinux" => { "policy_identity" => demo_identity, "policy" => {
        "port_inventory" => { "status" => "observed", "local_classification_status" => "observed", "mappings" => [{ "type" => "http_port_t", "protocol" => "tcp", "ports" => [{ "start" => 80, "end" => 80, "provenance" => "not_confirmed_custom" }] }] },
        "file_contexts" => [{ "pattern" => "/srv/www(/.*)?", "file_type" => "all files", "context" => "httpd_sys_content_t", "provenance" => "custom" }],
        "modules" => [{ "name" => "local_web", "priority" => 400, "provenance" => "unknown" }]
      } }
    })

    get "/api/v1/configuration", params: { family: "ports" }
    payload = JSON.parse(response.body)
    ports = payload.fetch("ports")
    expect(ports.fetch("coverage")).to eq("observed" => 1, "partial" => 0, "unavailable" => 0, "unknown" => 0, "stale" => 0, "no_heartbeat" => 0)
    expect(ports.fetch("policy_cohorts")).to eq([demo_identity])
    expect(ports.fetch("selected_policy_identity")).to eq(demo_identity)
    expect(ports.dig("catalog", "available")).to be true
    expect(ports.dig("catalog", "version")).to eq(catalog.content_digest)
    expect(ports.dig("catalog_overlay", "observed", "segments").map { |segment| segment.except("host_id") }).to eq([
      { "protocol" => "tcp", "start" => 80, "end" => 80, "catalog_types" => ["http_port_t"], "observed_types" => ["http_port_t"], "relation" => "matching_effective_type", "local_classification" => "not_confirmed_custom", "inventory_status" => "observed", "hostname" => "config-01" },
      { "protocol" => "tcp", "start" => 81, "end" => 90, "catalog_types" => ["http_port_t"], "observed_types" => [], "relation" => "catalog_defined_not_observed", "local_classification" => nil, "inventory_status" => "observed", "hostname" => "config-01" },
      { "protocol" => "tcp", "start" => 8080, "end" => 8080, "catalog_types" => ["http_port_t"], "observed_types" => [], "relation" => "catalog_defined_not_observed", "local_classification" => nil, "inventory_status" => "observed", "hostname" => "config-01" }
    ])

    get "/api/v1/configuration", params: { family: "file_contexts" }
    payload = JSON.parse(response.body)
    expect(payload.fetch("observed_host_count")).to eq(1)
    expect(payload.fetch("rows")).to eq([{ "pattern" => "/srv/www(/.*)?", "file_type" => "all files", "context" => "httpd_sys_content_t", "provenance" => ["custom"], "host_ids" => [host.id] }])

    get "/api/v1/configuration", params: { family: "modules" }
    payload = JSON.parse(response.body)
    expect(payload.fetch("observed_host_count")).to eq(1)
    expect(payload.fetch("rows")).to eq([{ "name" => "local_web", "priority" => 400, "version" => nil, "source_package" => nil, "provenance" => ["unknown"], "host_ids" => [host.id] }])
  end

  it "uses only fresh heartbeat configuration in rows families" do
    org = organization
    fresh = Host.create!(organization: org, external_id: "fresh-config", hostname: "fresh-config", last_seen_at: Time.current)
    stale = Host.create!(organization: org, external_id: "stale-config", hostname: "stale-config", last_seen_at: Time.current)
    event_only = Host.create!(organization: org, external_id: "event-only-config", hostname: "event-only-config", last_seen_at: Time.current)
    observe(fresh, { "selinux" => { "policy" => { "modules" => [{ "name" => "fresh_module", "provenance" => "policy" }] } } })
    observe(stale, { "selinux" => { "policy" => { "modules" => [{ "name" => "stale_module", "provenance" => "policy" }] } } }, at: 2.hours.ago, received_at: 1.hour.ago)
    HostSnapshot.create!(host: event_only, details: { "selinux" => { "policy" => { "modules" => [{ "name" => "event_module", "provenance" => "policy" }] } } })

    get "/api/v1/configuration", params: { family: "modules" }

    rows = JSON.parse(response.body).fetch("rows")
    expect(rows.map { |row| row["name"] }).to eq(["fresh_module"])
    expect(rows.first["host_ids"]).to eq([fresh.id])
  end

  it "keeps complete, empty, partial, unavailable, unknown, stale, and missing port inventory distinct" do
    import_demo_catalog
    org = organization
    observed = Host.create!(organization: org, external_id: "ports-observed", hostname: "ports-observed")
    empty = Host.create!(organization: org, external_id: "ports-empty", hostname: "ports-empty")
    partial = Host.create!(organization: org, external_id: "ports-partial", hostname: "ports-partial")
    unavailable = Host.create!(organization: org, external_id: "ports-unavailable", hostname: "ports-unavailable")
    unknown = Host.create!(organization: org, external_id: "ports-unknown", hostname: "ports-unknown")
    stale = Host.create!(organization: org, external_id: "ports-stale", hostname: "ports-stale")
    missing = Host.create!(organization: org, external_id: "ports-missing", hostname: "ports-missing")
    event_only = Host.create!(organization: org, external_id: "ports-event", hostname: "ports-event")
    inventory = lambda do |status, mappings = [], local = "observed"|
      { "selinux" => { "policy_identity" => demo_identity, "policy" => { "port_inventory" => { "status" => status, "local_classification_status" => local, "mappings" => mappings } } } }
    end
    mapping = [{ "type" => "http_port_t", "protocol" => "tcp", "ports" => [{ "start" => 8080, "end" => 8080, "provenance" => "not_confirmed_custom" }] }]
    observe(observed, inventory.call("observed", mapping))
    observe(empty, inventory.call("observed"))
    observe(partial, inventory.call("partial", mapping, "partial"))
    observe(unavailable, inventory.call("unavailable", [], "unavailable"))
    observe(unknown, inventory.call("unknown", [], "unknown"))
    observe(stale, inventory.call("observed", mapping), at: 2.hours.ago, received_at: 1.hour.ago)
    HostSnapshot.create!(host: event_only, details: inventory.call("observed", mapping))

    get "/api/v1/configuration", params: { family: "ports" }

    ports = JSON.parse(response.body).fetch("ports")
    expect(ports.fetch("coverage")).to eq("observed" => 2, "partial" => 1, "unavailable" => 1, "unknown" => 1, "stale" => 1, "no_heartbeat" => 2)
    expect(ports.dig("catalog_overlay", "observed", "fresh_complete_host_count")).to eq(2)
    expect(ports.dig("catalog_overlay", "observed", "stale_host_count")).to eq(1)
    expect(ports.dig("catalog_overlay", "observed", "outside_cohort_host_count")).to eq(2)
    expect(ports.dig("catalog_overlay", "observed", "no_current_configuration_host_count")).to eq(2)
    segments = ports.dig("catalog_overlay", "observed", "segments")
    expect(segments.map { |segment| segment["hostname"] }).not_to include("ports-stale", "ports-event")
    expect(segments.count { |segment| segment["relation"] == "catalog_defined_not_observed" && segment["start"] == 80 && segment["end"] == 90 }).to eq(2)
    expect(segments.count { |segment| segment["relation"] == "matching_effective_type" }).to eq(2)
    expect(segments.count { |segment| segment["relation"] == "comparison_unknown" }).to eq(1)
  end

  it "keeps observed port mappings visible when the selected cohort has no catalog" do
    identity = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    org = organization
    host = Host.create!(organization: org, external_id: "uncataloged-port", hostname: "uncataloged-port")
    observe(host, { "selinux" => { "policy_identity" => identity, "policy" => { "port_inventory" => { "status" => "observed", "local_classification_status" => "observed", "mappings" => [{ "type" => "http_port_t", "protocol" => "tcp", "ports" => [{ "start" => 8080, "end" => 8080, "provenance" => "custom" }] }] } } } })

    get "/api/v1/configuration", params: { family: "ports", policy_identity: identity }

    ports = JSON.parse(response.body).fetch("ports")
    expect(ports.dig("catalog", "available")).to be false
    expect(ports.dig("catalog_overlay", "observed", "segments")).to eq([])
    expect(ports.dig("catalog_overlay", "observed", "observed_mappings").map { |mapping| mapping.except("host_id") }).to eq([
      { "protocol" => "tcp", "type" => "http_port_t", "start" => 8080, "end" => 8080, "provenance" => "custom", "inventory_status" => "observed", "hostname" => "uncataloged-port" }
    ])
  end

  it "renders a selected catalog cohort without filling unknown observations" do
    import_demo_catalog
    other_identity = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    org = organization
    off = Host.create!(organization: org, external_id: "catalog-off", hostname: "catalog-off")
    unknown = Host.create!(organization: org, external_id: "catalog-unknown", hostname: "catalog-unknown")
    other = Host.create!(organization: org, external_id: "catalog-other", hostname: "catalog-other")
    observe(off, { "selinux" => { "policy_identity" => demo_identity, "boolean_status" => "observed", "booleans" => [{ "name" => "httpd_can_network_connect", "current" => false, "default" => false, "status" => "observed" }, { "name" => "unlisted_boolean", "current" => true, "status" => "observed" }] } })
    observe(unknown, { "selinux" => { "policy_identity" => demo_identity, "boolean_status" => "observed", "booleans" => [] } })
    observe(other, { "selinux" => { "policy_identity" => other_identity, "boolean_status" => "observed", "booleans" => [{ "name" => "httpd_can_network_connect", "current" => true, "status" => "observed" }] } })

    get "/api/v1/configuration", params: { family: "booleans", policy_identity: demo_identity }

    booleans = JSON.parse(response.body).fetch("booleans")
    expect(booleans.dig("catalog", "available")).to be true
    expect(booleans.dig("catalog", "version")).to eq("sha256:" + "d" * 64)
    expect(booleans.dig("catalog", "completeness")).to eq("complete")
    observed = booleans.dig("catalog_overlay", "observed")
    expect(observed).to include("fresh_host_count" => 2, "stale_host_count" => 0, "outside_cohort_host_count" => 1)
    rows = observed.fetch("rows").index_by { |row| row["name"] }
    expect(rows.fetch("httpd_can_network_connect").fetch("counts")).to include("on" => 0, "off" => 1, "unknown" => 1, "reference_match" => 1, "reference_difference" => 0)
    expect(rows.fetch("httpd_enable_cgi").fetch("counts")).to include("unknown" => 2)
    expect(rows.fetch("unlisted_boolean")).to include("catalog_status" => "not_defined")
    expect(rows.fetch("unlisted_boolean").fetch("counts")).to include("on" => 1, "unknown" => 1)
    expect(observed.fetch("unmatched_observed_names")).to eq(["unlisted_boolean"])
  end

  it "selects the first catalog-backed cohort when no policy identity is requested" do
    import_demo_catalog
    org = organization
    host = Host.create!(organization: org, external_id: "cohort-pick", hostname: "cohort-pick")
    observe(host, { "selinux" => { "policy_identity" => demo_identity, "boolean_status" => "observed", "booleans" => [] } })

    get "/api/v1/configuration", params: { family: "booleans" }

    booleans = JSON.parse(response.body).fetch("booleans")
    expect(booleans.fetch("selected_policy_identity")).to eq(demo_identity)
    expect(booleans.dig("catalog", "available")).to be true
  end
end
