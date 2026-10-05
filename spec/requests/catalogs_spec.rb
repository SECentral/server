require "rails_helper"

RSpec.describe "Catalogs API", type: :request do
  after do
    DistributionCatalogImport.delete_all
    DistributionCatalogBoolean.delete_all
    DistributionCatalogPort.delete_all
    DistributionCatalogRevision.delete_all
  end

  def catalog(**attributes)
    DistributionCatalogRevision.create!({
      schema_version: 1,
      content_digest: "sha256:" + "1" * 64,
      collector_semantics_version: 3,
      loaded_policy_digest: "sha256:" + "a" * 64,
      policy_type: "targeted",
      kernel_policy_version: 33,
      distribution: "almalinux",
      major_version: "9",
      architecture: "x86_64",
      policy_packages: [{ "name" => "selinux-policy-targeted", "version" => "38.1.75", "release" => "2.el9_8" }],
      booleans_complete: true,
      ports_complete: true
    }.merge(attributes)).tap do |revision|
      revision.distribution_catalog_booleans.create!(name: "httpd_can_network_connect", default_value: false, description: "Allow httpd network connections")
      revision.distribution_catalog_ports.create!(protocol: "tcp", start_port: 80, end_port: 90, selinux_type: "http_port_t")
      revision.distribution_catalog_ports.create!(protocol: "udp", start_port: 8080, end_port: 8080, selinux_type: "http_port_t")
    end
  end

  it "requires an authenticated operator" do
    get "/api/v1/catalogs"

    expect(response).to have_http_status(:unauthorized)
    get "/api/v1/catalogs/1"
    expect(response).to have_http_status(:unauthorized)
  end

  it "lists immutable catalog identity and family counts" do
    sign_in_operator
    revision = catalog

    get "/api/v1/catalogs"

    expect(response).to have_http_status(:ok)
    body = JSON.parse(response.body)
    expect(body["catalogs"].size).to eq(1)
    entry = body["catalogs"].first
    expect(entry).to include(
      "id" => revision.id,
      "display_name" => "AlmaLinux 9",
      "distribution" => "almalinux",
      "major_version" => "9",
      "architecture" => "x86_64",
      "policy_type" => "targeted",
      "kernel_policy_version" => 33,
      "schema_version" => 1,
      "collector_semantics_version" => 3,
      "content_digest" => revision.content_digest,
      "loaded_policy_digest" => revision.loaded_policy_digest,
      "booleans_complete" => true,
      "ports_complete" => true,
      "booleans_count" => 1,
      "port_mappings_count" => 2
    )
    expect(entry).not_to include("booleans", "port_mappings", "imports")
  end

  it "shows catalog detail with acquisition metadata and structured families" do
    sign_in_operator
    revision = catalog
    import = revision.distribution_catalog_imports.create!(artifact: "demo-artifact-bytes", acquisition_metadata: { "source" => "distribution-release" }, source_path: "artifacts/almalinux-9.json")

    get "/api/v1/catalogs/#{revision.id}"

    expect(response).to have_http_status(:ok)
    body = JSON.parse(response.body)["catalog"]
    expect(body["policy_packages"]).to eq([{ "name" => "selinux-policy-targeted", "version" => "38.1.75", "release" => "2.el9_8" }])
    expect(body["imports"].size).to eq(1)
    import_entry = body["imports"].first
    expect(import_entry["id"]).to eq(import.id)
    expect(import_entry["source_path"]).to eq("artifacts/almalinux-9.json")
    expect(import_entry["acquisition_metadata"]).to eq({ "source" => "distribution-release" })
    expect(Time.parse(import_entry["imported_at"])).to be_within(1.second).of(import.created_at)
    expect(body["booleans"]).to eq([{ "name" => "httpd_can_network_connect", "default_value" => false, "description" => "Allow httpd network connections" }])
    expect(body["port_mappings"]).to eq(
      [{ "protocol" => "tcp", "start" => 80, "end" => 90, "type" => "http_port_t" },
       { "protocol" => "udp", "start" => 8080, "end" => 8080, "type" => "http_port_t" }]
    )
  end

  it "returns 404 for an unknown catalog" do
    sign_in_operator

    get "/api/v1/catalogs/999999"

    expect(response).to have_http_status(:not_found)
  end
end
