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
      "lifecycle" => "active",
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

  it "authenticates management operations and enforces CSRF protection" do
    sign_out_operator
    revision = catalog
    patch "/api/v1/catalogs/#{revision.id}/name", params: { display_name: "Name" }, as: :json
    expect(response).to have_http_status(:unauthorized)
    post "/api/v1/catalogs/#{revision.id}/archive"
    expect(response).to have_http_status(:unauthorized)
    post "/api/v1/catalogs/#{revision.id}/unarchive"
    expect(response).to have_http_status(:unauthorized)

    original = Api::V1::BaseController.config.allow_forgery_protection
    Api::V1::BaseController.config.allow_forgery_protection = true
    get "/api/v1/sessions"
    token = response.headers["X-CSRF-Token"]
    post "/api/v1/sessions", params: { username: "test-admin", password: "test-password" }, headers: { "X-CSRF-Token" => token }, as: :json
    token = response.headers["X-CSRF-Token"]
    post "/api/v1/catalogs/#{revision.id}/archive"
    expect(response).to have_http_status(:unprocessable_content)
    expect(JSON.parse(response.body).dig("error", "code")).to eq("invalid_csrf_token")
    post "/api/v1/catalogs/#{revision.id}/archive", headers: { "X-CSRF-Token" => token }
    expect(response).to have_http_status(:ok)
  ensure
    Api::V1::BaseController.config.allow_forgery_protection = original unless original.nil?
    sign_out_operator
  end

  it "renames, archives and unarchives without touching immutable content or import evidence" do
    sign_in_operator
    result = ImportDistributionCatalog.call(artifact: DistributionCatalogArtifact.read(Rails.root.join("spec/fixtures/catalogs/v3.json")))
    revision = result.revision
    original = revision.attributes
    import = result.catalog_import.attributes

    patch "/api/v1/catalogs/#{revision.id}/name", params: { display_name: "  Organizational-looking name  " }, as: :json
    expect(response).to have_http_status(:ok)
    expect(JSON.parse(response.body)["catalog"]).to include("display_name" => "Organizational-looking name", "lifecycle" => "active", "content_digest" => original["content_digest"])
    get "/api/v1/catalogs"
    expect(JSON.parse(response.body)["catalogs"].first["display_name"]).to eq("Organizational-looking name")

    2.times { post "/api/v1/catalogs/#{revision.id}/archive" }
    expect(JSON.parse(response.body)["catalog"]).to include("lifecycle" => "archived", "content_digest" => original["content_digest"])
    get "/api/v1/catalogs/#{revision.id}"
    expect(response).to have_http_status(:ok)
    expect(JSON.parse(response.body).dig("catalog", "imports").size).to eq(1)
    expect(DistributionCatalogRevision.active).to be_empty
    get "/api/v1/catalogs"
    expect(JSON.parse(response.body)["catalogs"].first["lifecycle"]).to eq("archived")

    2.times { post "/api/v1/catalogs/#{revision.id}/unarchive" }
    expect(JSON.parse(response.body)["catalog"]["lifecycle"]).to eq("active")
    expect(revision.reload.attributes).to eq(original)
    expect(result.catalog_import.reload.attributes).to eq(import)
    expect(revision.catalog_management.catalog_management_changes.count).to eq(3)
  end

  it "rejects invalid names and all extra/immutable inputs, without offering delete" do
    sign_in_operator
    revision = catalog
    [nil, 42, {}, " ", "a" * 121, "line\nname"].each do |name|
      patch "/api/v1/catalogs/#{revision.id}/name", params: { display_name: name }, as: :json
      expect(response).to have_http_status(:unprocessable_content)
    end
    %w[content_digest loaded_policy_digest catalog platform families id reference_class lifecycle].each do |key|
      patch "/api/v1/catalogs/#{revision.id}/name", params: { display_name: "Name", key => "mutated" }, as: :json
      expect(response).to have_http_status(:unprocessable_content), key
    end
    post "/api/v1/catalogs/#{revision.id}/archive", params: { content_digest: "mutated" }, as: :json
    expect(response).to have_http_status(:unprocessable_content)
    expect(revision.catalog_management.reload).to have_attributes(display_name: "AlmaLinux 9", lifecycle: "active")
    expect(Rails.application.routes.routes.none? { |route| route.verb == "DELETE" && route.defaults[:controller] == "api/v1/catalogs" }).to be(true)
  end

  it "does not introduce per-revision management queries in the list" do
    sign_in_operator
    3.times { |i| catalog(content_digest: "sha256:#{i.to_s * 64}", loaded_policy_digest: "sha256:#{(i + 1).to_s * 64}") }
    queries = []
    subscriber = ActiveSupport::Notifications.subscribe("sql.active_record") do |*, payload|
      queries << payload[:sql] if payload[:sql].start_with?("SELECT") && payload[:sql].include?("catalog_managements")
    end
    get "/api/v1/catalogs"
    expect(response).to have_http_status(:ok)
    expect(queries.size).to eq(1)
  ensure
    ActiveSupport::Notifications.unsubscribe(subscriber) if subscriber
  end
end
