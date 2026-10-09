require "rails_helper"

RSpec.describe "Catalog product import", type: :request do
  include ActiveSupport::Testing::TimeHelpers

  let(:bytes) { File.binread(Rails.root.join("spec/fixtures/catalogs/v3.json")) }
  before { sign_in_operator }
  after do
    DistributionCatalogImport.delete_all
    DistributionCatalogBoolean.delete_all
    DistributionCatalogPort.delete_all
    DistributionCatalogRevision.delete_all
  end

  def counts
    [DistributionCatalogRevision, DistributionCatalogBoolean, DistributionCatalogPort, DistributionCatalogImport, CatalogManagement, CatalogManagementChange].map(&:count)
  end

  def upload(action, value = bytes, name: nil, token: nil, headers: {})
    query = name.nil? ? "" : "?display_name=#{ERB::Util.url_encode(name)}"
    post "/api/v1/catalogs/import-#{action}#{query}", params: value, headers: { "CONTENT_TYPE" => "application/octet-stream", "X-Catalog-Preview" => token }.merge(headers)
  end

  def preview(value = bytes, **options)
    upload("preview", value, **options)
    expect(response).to have_http_status(:ok)
    JSON.parse(response.body).fetch("preview")
  end

  def changed_bytes
    value = JSON.parse(bytes)
    value.dig("catalog", "families", "booleans", "entries", 0)["description"] = "Controlled conflicting description"
    value["content_digest"] = "sha256:#{Digest::SHA256.hexdigest(DistributionCatalogCanonicalizer.call(value.fetch('catalog')))}"
    JSON.generate(value)
  end

  it "previews without any catalog persistence and confirms exact bytes with name/source evidence" do
    original = counts
    result = preview(name: "  Named reference  ")
    expect(counts).to eq(original)
    expect(result).to include("outcome" => "create_new_revision", "display_name" => "Named reference", "supported" => true, "validation_status" => "valid", "schema_version" => 1, "collector_semantics_version" => 3)
    expect(result["families"]).to eq("booleans" => { "status" => "complete", "count" => 2 }, "ports" => { "status" => "complete", "count" => 2, "protocols" => %w[tcp udp sctp dccp] })
    expect(result["acquisition"].keys).to match_array(%w[collected_at collector_version])
    upload("confirm", token: result.fetch("preview_token"))
    expect(response).to have_http_status(:created)
    body = JSON.parse(response.body)
    revision = DistributionCatalogRevision.find(body.dig("catalog", "id"))
    expect(revision.catalog_management).to have_attributes(display_name: "Named reference", lifecycle: "active")
    expect(revision.distribution_catalog_imports.first).to have_attributes(artifact: bytes, imported_by: "test-admin", source_kind: "operator_upload", source_path: nil)
    expect(CatalogManagementChange.count).to eq(0)
    expect(body["catalog"]["content_digest"]).to eq(result["content_digest"])
  end

  it "uses the derived default and keeps renamed archived duplicates unchanged, including retries" do
    result = preview
    expect(result["display_name"]).to eq("Example 9")
    upload("confirm", token: result["preview_token"])
    revision = DistributionCatalogRevision.first
    revision.catalog_management.change!(display_name: "Retained name", lifecycle: "archived", changed_by: "operator")
    immutable = revision.attributes
    original_changes = CatalogManagementChange.count
    reused = preview(name: "Another submitted name")
    expect(reused).to include("outcome" => "reuse_existing_revision", "display_name" => "Retained name")
    expect(reused["existing_revision"]).to include("id" => revision.id, "lifecycle" => "archived")
    2.times do
      upload("confirm", token: reused["preview_token"])
      expect(response).to have_http_status(:ok)
      expect(JSON.parse(response.body)).to include("outcome" => "reuse_existing_revision")
    end
    expect(revision.reload.attributes).to eq(immutable)
    expect(revision.catalog_management).to have_attributes(display_name: "Retained name", lifecycle: "archived")
    expect(DistributionCatalogRevision.count).to eq(1)
    expect(DistributionCatalogImport.count).to eq(3)
    expect(CatalogManagementChange.count).to eq(original_changes)
  end

  it "reports conflicts without receipts and rechecks stale create previews" do
    create = preview
    ImportDistributionCatalog.call(artifact: DistributionCatalogArtifact.new(bytes))
    upload("confirm", token: create["preview_token"])
    expect(response).to have_http_status(:ok)
    expect(JSON.parse(response.body)["outcome"]).to eq("reuse_existing_revision")
    conflict = preview(changed_bytes)
    expect(conflict).to include("outcome" => "conflict", "preview_token" => nil)
    expect(DistributionCatalogImport.count).to eq(2)
  end

  it "rejects conflicts inserted after preview atomically" do
    result = preview
    ImportDistributionCatalog.call(artifact: DistributionCatalogArtifact.new(changed_bytes))
    original = counts
    upload("confirm", token: result["preview_token"])
    expect(response).to have_http_status(:conflict)
    expect(JSON.parse(response.body).dig("error", "code")).to eq("loaded_policy_conflict")
    expect(counts).to eq(original)
  end

  {
    "unsupported_schema" => ->(value) { value["schema_version"] = 4 },
    "unsupported_collector_semantics" => ->(value) { value["catalog"]["collector_semantics_version"] = 2 },
    "digest_mismatch" => ->(value) { value["content_digest"] = "sha256:" + "0" * 64 },
    "invalid_identity" => ->(value) { value["catalog"]["policy"]["loaded_policy_digest"] = "invalid" },
    "invalid_provenance" => ->(value) { value["metadata"]["collected_at"] = 42 },
    "invalid_boolean_family" => ->(value) { value["catalog"]["families"].delete("booleans") },
    "invalid_port_family" => ->(value) { value["catalog"]["families"]["ports"]["mappings"][0]["protocol"] = "icmp" },
    "invalid_artifact" => ->(value) { value["catalog"]["families"]["fcontexts"] = {} }
  }.each do |code, mutate|
    it "returns safe #{code} errors with no persistence" do
      value = JSON.parse(bytes)
      mutate.call(value)
      original = counts
      upload("preview", JSON.generate(value))
      expect(response).to have_http_status(:unprocessable_content)
      expect(JSON.parse(response.body).dig("error", "code")).to eq(code)
      expect(counts).to eq(original)
    end
  end

  it "bounds uploads/JSON/families and never exposes parser snippets or paths" do
    original = counts
    { "" => "empty_upload", "\xff".b => "invalid_encoding", '{"private":"/tmp/secret-path"' => "malformed_json", "[" * 40 + "0" + "]" * 40 => "malformed_json", "x" * (DistributionCatalogArtifact::MAX_BYTES + 1) => "upload_too_large" }.each do |value, code|
      upload("preview", value)
      expect(JSON.parse(response.body).dig("error", "code")).to eq(code)
      expect(response.body).not_to include("secret-path")
    end
    value = JSON.parse(bytes)
    value["catalog"]["families"]["booleans"]["entries"] = Array.new(20_001) { { "name" => "a", "default" => false, "description" => "" } }
    upload("preview", JSON.generate(value))
    expect(JSON.parse(response.body).dig("error", "code")).to eq("invalid_boolean_family")
    upload("preview", bytes, headers: { "CONTENT_TYPE" => "application/json" })
    expect(response).to have_http_status(:unsupported_media_type)
    expect(counts).to eq(original)
  end

  it "rejects invalid names without creating management data" do
    [" ", "a" * 121, "line\nname"].each do |name|
      upload("preview", name: name)
      expect(JSON.parse(response.body).dig("error", "code")).to eq("invalid_display_name")
    end
    expect(counts).to eq([0, 0, 0, 0, 0, 0])
  end

  it "binds confirmation to raw bytes, session, expiry and revalidation" do
    result = preview
    upload("confirm", bytes + "\n", token: result["preview_token"])
    expect(JSON.parse(response.body).dig("error", "code")).to eq("preview_bytes_changed")
    RSpec::Mocks.with_temporary_scope do
      allow_any_instance_of(DistributionCatalogArtifact).to receive(:validate!).and_raise(DistributionCatalogArtifact::Invalid.new("Revalidation failed", code: "digest_mismatch"))
      upload("confirm", token: result["preview_token"])
      expect(JSON.parse(response.body).dig("error", "code")).to eq("digest_mismatch")
    end
    travel 11.minutes do
      upload("confirm", token: result["preview_token"])
      expect(JSON.parse(response.body).dig("error", "code")).to eq("invalid_preview")
    end
    sign_out_operator
    sign_in_operator
    upload("confirm", token: result["preview_token"])
    expect(JSON.parse(response.body).dig("error", "code")).to eq("invalid_preview")
    expect(counts).to eq([0, 0, 0, 0, 0, 0])
  end

  it "requires operator authentication and CSRF for preview and confirmation" do
    sign_out_operator
    %w[preview confirm].each do |action|
      upload(action)
      expect(response).to have_http_status(:unauthorized)
    end
    sign_in_operator
    original = Api::V1::BaseController.config.allow_forgery_protection
    Api::V1::BaseController.config.allow_forgery_protection = true
    %w[preview confirm].each do |action|
      upload(action)
      expect(JSON.parse(response.body).dig("error", "code")).to eq("invalid_csrf_token")
    end
    get "/api/v1/sessions"
    result = preview(headers: { "X-CSRF-Token" => response.headers["X-CSRF-Token"] })
    upload("confirm", token: result["preview_token"], headers: { "X-CSRF-Token" => response.headers["X-CSRF-Token"] })
    expect(response).to have_http_status(:created)
  ensure
    Api::V1::BaseController.config.allow_forgery_protection = original unless original.nil?
  end

  it "confirms from two independent operator sessions without duplicate semantic state" do
    raw = bytes
    sessions = 2.times.map do
      client = ActionDispatch::Integration::Session.new(Rails.application)
      client.post("/api/v1/sessions", params: { username: "test-admin", password: "test-password" })
      client.post("/api/v1/catalogs/import-preview", params: raw, headers: { "CONTENT_TYPE" => "application/octet-stream" })
      [client, JSON.parse(client.response.body).dig("preview", "preview_token")]
    end
    threads = sessions.map do |client, token|
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          client.post("/api/v1/catalogs/import-confirm", params: raw, headers: { "CONTENT_TYPE" => "application/octet-stream", "X-Catalog-Preview" => token })
          client.response.status
        end
      end
    end
    expect(threads.map(&:value)).to contain_exactly(200, 201)
    expect([DistributionCatalogRevision, CatalogManagement, DistributionCatalogImport].map(&:count)).to eq([1, 1, 2])
  end

  it "rejects forged receipts and unexpected client authority fields" do
    upload("confirm", token: "forged")
    expect(JSON.parse(response.body).dig("error", "code")).to eq("invalid_preview")
    post "/api/v1/catalogs/import-preview?source_path=/private/path", params: bytes, headers: { "CONTENT_TYPE" => "application/octet-stream" }
    expect(JSON.parse(response.body).dig("error", "code")).to eq("invalid_upload")
    expect(response.body).not_to include("/private/path")
    expect(counts).to eq([0, 0, 0, 0, 0, 0])
  end
end
