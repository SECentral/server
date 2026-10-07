require "rails_helper"

RSpec.describe "Host SELinux configuration API", type: :request do
  let(:identity) { "sha256:" + "a" * 64 }

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

  def revision
    DistributionCatalogRevision.create!(schema_version: 1, content_digest: "sha256:" + "1" * 64, collector_semantics_version: 3, loaded_policy_digest: identity, policy_type: "targeted", kernel_policy_version: 33, distribution: "almalinux", major_version: "9", architecture: "x86_64", policy_packages: [{ "name" => "selinux-policy-targeted", "version" => "38.1.75" }], booleans_complete: true, ports_complete: true).tap do |catalog|
      catalog.distribution_catalog_booleans.create!(name: "httpd_can_network_connect", default_value: false, description: "Allow network")
      catalog.distribution_catalog_booleans.create!(name: "named_file_trusted_context", default_value: true, description: "Trust named files")
      catalog.distribution_catalog_ports.create!(protocol: "tcp", start_port: 8080, end_port: 8080, selinux_type: "http_port_t")
    end
  end

  def observe(host, details, observed_at: Time.current, received_at: Time.current)
    snapshot = HostSnapshot.create!(host: host, details: details)
    installation = host.organization.agent_installations.create!(name: "agent-#{host.external_id}", bound_host: host)
    host.host_snapshot_observations.create!(agent_installation: installation, host_snapshot: snapshot, first_observed_at: observed_at, last_observed_at: observed_at, first_received_at: received_at, last_received_at: received_at)
  end

  def host(details, observed_at: Time.current, received_at: Time.current)
    organization = Organization.create!(name: "configuration-#{SecureRandom.uuid}")
    record = organization.hosts.create!(external_id: SecureRandom.uuid, hostname: "alma-01")
    observe(record, details, observed_at: observed_at, received_at: received_at)
    record
  end

  def demo_host
    host({ "selinux" => {
      "policy_identity" => "sha256:" + "b" * 64,
      "configured_policy_type" => "targeted",
      "boolean_status" => "observed",
      "booleans" => [
        { "name" => "httpd_can_network_connect", "current" => true, "default" => false, "status" => "observed" },
        { "name" => "named_file_trusted_context", "current" => true, "default" => true, "status" => "observed" },
        { "name" => "extra_local_boolean", "current" => true, "default" => true, "status" => "observed" }
      ],
      "policy" => { "port_inventory" => { "status" => "observed", "mappings" => [
        { "type" => "http_port_t", "protocol" => "tcp", "ports" => [{ "start" => 8080, "end" => 8080, "provenance" => "not_confirmed_custom" }] },
        { "type" => "my_app_port_t", "protocol" => "tcp", "ports" => [{ "start" => 8443, "end" => 8443, "provenance" => "custom" }] }
      ] } }
    }, "platform" => { "os_id" => "almalinux", "os_version" => "9.3", "architecture" => "amd64" }
    })
  end

  it "requires an operator session" do
    sign_out_operator
    record = demo_host

    get "/api/v1/hosts/#{record.id}/configuration"

    expect(response).to have_http_status(:unauthorized)
  end

  it "returns 404 for an unknown host" do
    get "/api/v1/hosts/999999/configuration"

    expect(response).to have_http_status(:not_found)
  end

  it "exposes host facts, observation freshness, and the selected reference" do
    catalog = revision
    observed_at = Time.current.change(usec: 0)
    record = host({ "selinux" => {
      "policy_identity" => "sha256:" + "b" * 64,
      "configured_policy_type" => "targeted",
      "boolean_status" => "observed",
      "booleans" => [
        { "name" => "httpd_can_network_connect", "current" => true, "default" => false, "status" => "observed" },
        { "name" => "named_file_trusted_context", "current" => true, "default" => true, "status" => "observed" },
        { "name" => "extra_local_boolean", "current" => true, "default" => true, "status" => "observed" }
      ],
      "policy" => { "port_inventory" => { "status" => "observed", "mappings" => [
        { "type" => "http_port_t", "protocol" => "tcp", "ports" => [{ "start" => 8080, "end" => 8080, "provenance" => "not_confirmed_custom" }] },
        { "type" => "my_app_port_t", "protocol" => "tcp", "ports" => [{ "start" => 8443, "end" => 8443, "provenance" => "custom" }] }
      ] } }
    }, "platform" => { "os_id" => "almalinux", "os_version" => "9.3", "architecture" => "amd64" } }, observed_at: observed_at, received_at: observed_at)

    get "/api/v1/hosts/#{record.id}/configuration"

    expect(response).to have_http_status(:ok)
    payload = JSON.parse(response.body)
    expect(payload.fetch("host")).to eq("id" => record.id, "hostname" => "alma-01", "external_id" => record.external_id)
    expect(payload.fetch("observation")).to include("status" => "current", "last_observed_at" => observed_at.iso8601(3))
    expect(payload.fetch("selinux").except("effective_permissive_domains")).to eq("enforcement" => nil, "configured_policy_type" => "targeted", "boolean_status" => "observed", "port_inventory_status" => "observed", "file_context_mappings_status" => "unknown", "policy_identity" => "sha256:" + "b" * 64)
    expect(payload.dig("selinux", "effective_permissive_domains")).to include("status" => "unavailable", "domains" => nil, "policy_identity" => "sha256:" + "b" * 64)
    expect(payload.fetch("reference")).to eq("kind" => "distribution_catalog", "catalog_revision" => {
      "id" => catalog.id, "display_name" => "AlmaLinux 9", "policy_type" => "targeted", "architecture" => "x86_64", "loaded_policy_digest" => identity, "applicability" => "major_release"
    })
    expect(payload.fetch("comparison")).to eq("available" => true, "paused" => false, "summary" => {
      "booleans" => { "reference_entries" => 2, "compared" => 2, "match" => 1, "differ" => 1, "host_only" => 1, "not_observed" => 0, "unavailable" => 0 },
      "ports" => { "compared" => 2, "match" => 1, "differ" => 1, "not_observed" => 0 }
    })
    expect(payload.fetch("view")).to eq("differences")
  end

  it "defaults to a differences view with structured findings" do
    revision
    record = demo_host

    get "/api/v1/hosts/#{record.id}/configuration"

    differences = JSON.parse(response.body).fetch("differences")
    expect(differences.fetch("total")).to eq(3)
    expect(differences.fetch("booleans")).to eq([
      { "name" => "httpd_can_network_connect", "kind" => "differs", "reference_default" => false, "observed_current" => true, "host_reported_default" => false, "description" => "Allow network" },
      { "name" => "extra_local_boolean", "kind" => "host_only", "reference_default" => nil, "observed_current" => true, "host_reported_default" => true, "description" => nil }
    ])
    expect(differences.fetch("ports")).to eq([{ "protocol" => "tcp", "start" => 8443, "end" => 8443, "catalog_types" => [], "observed_types" => ["my_app_port_t"], "relation" => "observed_not_represented", "local_classification" => "custom", "inventory_status" => "observed" }])
    expect(differences.fetch("limitations")).to eq("reference_only_booleans" => [], "unavailable_booleans" => [], "port_segments" => [])
  end

  it "reports zero differences with reference-only limitation for a clean host" do
    revision
    record = host({ "selinux" => {
      "policy_identity" => "sha256:" + "b" * 64,
      "configured_policy_type" => "targeted",
      "boolean_status" => "observed",
      "booleans" => [{ "name" => "named_file_trusted_context", "current" => true, "default" => true, "status" => "observed" }],
      "policy" => { "port_inventory" => { "status" => "observed", "mappings" => [
        { "type" => "http_port_t", "protocol" => "tcp", "ports" => [{ "start" => 8080, "end" => 8080, "provenance" => "not_confirmed_custom" }] }
      ] } }
    }, "platform" => { "os_id" => "almalinux", "os_version" => "9.3", "architecture" => "amd64" } })

    get "/api/v1/hosts/#{record.id}/configuration"

    payload = JSON.parse(response.body)
    expect(payload.dig("comparison", "summary", "booleans")).to eq("reference_entries" => 2, "compared" => 1, "match" => 1, "differ" => 0, "host_only" => 0, "not_observed" => 1, "unavailable" => 0)
    expect(payload.dig("comparison", "summary", "ports")).to eq("compared" => 1, "match" => 1, "differ" => 0, "not_observed" => 0)
    differences = payload.fetch("differences")
    expect(differences.fetch("total")).to eq(0)
    expect(differences.fetch("booleans")).to be_empty
    expect(differences.fetch("ports")).to be_empty
    expect(differences.dig("limitations", "reference_only_booleans")).to eq(["httpd_can_network_connect"])
  end

  it "returns full flat boolean rows in the booleans view" do
    revision
    record = demo_host

    get "/api/v1/hosts/#{record.id}/configuration", params: { view: "booleans" }

    booleans = JSON.parse(response.body).fetch("booleans")
    expect(booleans).to include("total" => 3, "page" => 1, "page_size" => 50, "pages" => 1)
    expect(booleans.fetch("rows")).to eq([
      { "name" => "httpd_can_network_connect", "current" => true, "host_default" => false, "reference_default" => false, "description" => "Allow network", "catalog_status" => "defined", "status" => "observed" },
      { "name" => "extra_local_boolean", "current" => true, "host_default" => true, "reference_default" => nil, "description" => nil, "catalog_status" => "not_defined", "status" => "observed" },
      { "name" => "named_file_trusted_context", "current" => true, "host_default" => true, "reference_default" => true, "description" => "Trust named files", "catalog_status" => "defined", "status" => "observed" }
    ])
  end

  it "pages and searches the booleans view" do
    catalog = revision
    55.times do |index|
      catalog.distribution_catalog_booleans.create!(name: "padding_bool_#{format("%02d", index)}", default_value: false, description: "Padding boolean #{format("%02d", index)}")
    end
    record = host({ "selinux" => {
      "policy_identity" => "sha256:" + "b" * 64,
      "configured_policy_type" => "targeted",
      "boolean_status" => "observed",
      "booleans" => (0...55).map { |index| { "name" => "padding_bool_#{format("%02d", index)}", "current" => false, "default" => false, "status" => "observed" } } + [
        { "name" => "httpd_can_network_connect", "current" => true, "default" => false, "status" => "observed" }
      ],
      "policy" => { "port_inventory" => { "status" => "observed", "mappings" => [] } }
    }, "platform" => { "os_id" => "almalinux", "os_version" => "9.3", "architecture" => "amd64" } })

    get "/api/v1/hosts/#{record.id}/configuration", params: { view: "booleans" }
    page = JSON.parse(response.body).fetch("booleans")
    expect(page).to include("total" => 57, "pages" => 2, "page" => 1)
    expect(page.dig("rows", 0, "name")).to eq("httpd_can_network_connect")
    expect(page.fetch("rows").map { |row| row["name"] }).not_to include("padding_bool_50")

    get "/api/v1/hosts/#{record.id}/configuration", params: { view: "booleans", page: 2 }
    page = JSON.parse(response.body).fetch("booleans")
    expect(page).to include("total" => 57, "pages" => 2, "page" => 2)
    expect(page.fetch("rows").map { |row| row["name"] }).to include("padding_bool_50")

    get "/api/v1/hosts/#{record.id}/configuration", params: { view: "booleans", q: "padding_bool_5" }
    page = JSON.parse(response.body).fetch("booleans")
    expect(page.fetch("total")).to eq(5)
    expect(page.fetch("rows").map { |row| row["name"] }).to eq(%w[padding_bool_50 padding_bool_51 padding_bool_52 padding_bool_53 padding_bool_54])

    get "/api/v1/hosts/#{record.id}/configuration", params: { view: "booleans", q: "Padding boolean 07" }
    page = JSON.parse(response.body).fetch("booleans")
    expect(page.fetch("rows")).to eq([{ "name" => "padding_bool_07", "current" => false, "host_default" => false, "reference_default" => false, "description" => "Padding boolean 07", "catalog_status" => "defined", "status" => "observed" }])
  end

  it "returns port segments with provenance in the ports view and supports search" do
    revision
    record = demo_host

    get "/api/v1/hosts/#{record.id}/configuration", params: { view: "ports" }
    ports = JSON.parse(response.body).fetch("ports")
    expect(ports).to include("total" => 2, "pages" => 1)
    expect(ports.fetch("segments")).to eq([
      { "protocol" => "tcp", "start" => 8443, "end" => 8443, "catalog_types" => [], "observed_types" => ["my_app_port_t"], "relation" => "observed_not_represented", "local_classification" => "custom", "inventory_status" => "observed" },
      { "protocol" => "tcp", "start" => 8080, "end" => 8080, "catalog_types" => ["http_port_t"], "observed_types" => ["http_port_t"], "relation" => "matching_effective_type", "local_classification" => "not_confirmed_custom", "inventory_status" => "observed" }
    ])

    get "/api/v1/hosts/#{record.id}/configuration", params: { view: "ports", q: "8443" }
    ports = JSON.parse(response.body).fetch("ports")
    expect(ports.fetch("total")).to eq(1)
    expect(ports.dig("segments", 0, "end")).to eq(8443)

    get "/api/v1/hosts/#{record.id}/configuration", params: { view: "ports", q: "port_t" }
    expect(JSON.parse(response.body).dig("ports", "total")).to eq(2)
  end

  it "falls back to the differences view for unknown views" do
    revision
    record = demo_host

    get "/api/v1/hosts/#{record.id}/configuration", params: { view: "inventory" }

    payload = JSON.parse(response.body)
    expect(payload.fetch("view")).to eq("differences")
    expect(payload.dig("differences", "total")).to eq(3)
  end

  it "pauses comparison and keeps last-observed data for stale observations" do
    revision
    record = host({ "selinux" => {
      "policy_identity" => identity,
      "boolean_status" => "unavailable",
      "policy" => { "port_inventory" => { "status" => "partial", "mappings" => [] } }
    } }, observed_at: 1.hour.ago, received_at: 1.hour.ago)

    get "/api/v1/hosts/#{record.id}/configuration"
    payload = JSON.parse(response.body)
    expect(payload.dig("observation", "status")).to eq("stale")
    expect(payload.dig("comparison", "paused")).to be true
    expect(payload.dig("reference", "catalog_revision", "applicability")).to eq("exact")
    expect(payload.dig("differences", "total")).to eq(0)

    get "/api/v1/hosts/#{record.id}/configuration", params: { view: "booleans" }
    booleans = JSON.parse(response.body).fetch("booleans")
    expect(booleans.fetch("total")).to eq(2)
    expect(booleans.fetch("rows").map { |row| row["status"] }).to eq(%w[stale stale])
  end

  it "keeps unknown and unavailable host values from being read as Off" do
    unknown = host({ "selinux" => { "boolean_status" => "observed", "booleans" => [{ "name" => "virt_use_nfs", "current" => false, "persistent" => false, "status" => "unknown" }] } })

    get "/api/v1/hosts/#{unknown.id}/configuration", params: { view: "booleans" }
    payload = JSON.parse(response.body)
    expect(payload.dig("reference", "kind")).to eq("none")
    expect(payload.dig("comparison", "available")).to be false
    expect(payload.dig("booleans", "rows")).to eq([{ "name" => "virt_use_nfs", "current" => nil, "host_default" => false, "reference_default" => nil, "description" => nil, "catalog_status" => "unavailable", "status" => "unknown" }])

    unavailable = host({ "selinux" => { "boolean_status" => "unavailable" } })
    get "/api/v1/hosts/#{unavailable.id}/configuration", params: { view: "booleans" }
    payload = JSON.parse(response.body)
    expect(payload.dig("selinux", "boolean_status")).to eq("unavailable")
    expect(payload.dig("booleans", "rows")).to be_empty
  end

  it "exposes null facts for hosts without a heartbeat-confirmed observation" do
    organization = Organization.create!(name: "event-only-configuration")
    record = organization.hosts.create!(external_id: "event-only", hostname: "event-only")
    HostSnapshot.create!(host: record, details: { "selinux" => { "boolean_status" => "observed", "booleans" => [{ "name" => "virt_use_nfs", "current" => true, "status" => "observed" }] } })

    get "/api/v1/hosts/#{record.id}/configuration"

    payload = JSON.parse(response.body)
    expect(payload.fetch("observation")).to be_nil
    expect(payload.fetch("selinux").except("effective_permissive_domains")).to eq("enforcement" => nil, "configured_policy_type" => nil, "boolean_status" => nil, "port_inventory_status" => "unknown", "file_context_mappings_status" => "unknown", "policy_identity" => nil)
    expect(payload.dig("selinux", "effective_permissive_domains")).to include("status" => "unavailable", "domains" => nil, "policy_identity" => nil)
    expect(payload.fetch("reference")).to eq("kind" => "none")
    expect(payload.dig("comparison", "available")).to be false
    expect(payload.dig("comparison", "summary")).to eq("booleans" => nil, "ports" => nil)
    expect(payload["differences"]).to be_nil
  end

  it "reports no reference when no catalog has been imported" do
    record = host({ "selinux" => { "policy_identity" => "sha256:" + "c" * 64, "boolean_status" => "observed", "booleans" => [] } })

    get "/api/v1/hosts/#{record.id}/configuration"

    payload = JSON.parse(response.body)
    expect(payload.fetch("reference")).to eq("kind" => "none")
    expect(payload.dig("comparison", "available")).to be false
  end
end
