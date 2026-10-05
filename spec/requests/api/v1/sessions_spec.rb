require "rails_helper"

RSpec.describe "API v1 sessions", type: :request do
  let(:json_headers) { { "CONTENT_TYPE" => "application/json" } }

  # The test environment disables forgery protection globally; these specs
  # exercise the API's CSRF behavior, so re-enable it for Api::V1 only.
  around do |example|
    original = Api::V1::BaseController.config.allow_forgery_protection
    Api::V1::BaseController.config.allow_forgery_protection = true
    example.run
  ensure
    Api::V1::BaseController.config.allow_forgery_protection = original
  end

  def sign_in_via_api
    post "/api/v1/sessions", params: { username: "test-admin", password: "test-password" }.to_json, headers: json_headers
  end

  it "returns 401 JSON for anonymous requests" do
    get "/api/v1/sessions"

    expect(response).to have_http_status(:unauthorized)
    expect(JSON.parse(response.body)).to eq("error" => { "code" => "unauthorized", "message" => "Authentication required" })
  end

  it "creates a session with valid credentials without requiring CSRF" do
    sign_in_via_api

    expect(response).to have_http_status(:created)
    expect(response.headers["X-CSRF-Token"]).to be_present
    expect(JSON.parse(response.body)).to eq("operator" => { "username" => "test-admin" })
  end

  it "rejects invalid credentials with one generic 401" do
    post "/api/v1/sessions", params: { username: "test-admin", password: "wrong" }.to_json, headers: json_headers

    expect(response).to have_http_status(:unauthorized)
    expect(JSON.parse(response.body)).to eq("error" => { "code" => "unauthorized", "message" => "Invalid credentials" })
  end

  it "shows the operator and a CSRF token for an authenticated session" do
    sign_in_via_api
    expect(response).to have_http_status(:created)

    get "/api/v1/sessions"

    expect(response).to have_http_status(:ok)
    expect(response.headers["X-CSRF-Token"]).to be_present
    expect(JSON.parse(response.body)).to eq("operator" => { "username" => "test-admin" })
  end

  it "clears the session on delete with a valid CSRF token" do
    sign_in_via_api
    token = response.headers["X-CSRF-Token"]

    delete "/api/v1/sessions", headers: { "X-CSRF-Token" => token }

    expect(response).to have_http_status(:no_content)

    get "/api/v1/sessions"
    expect(response).to have_http_status(:unauthorized)
  end

  it "rejects delete without a CSRF token and keeps the session" do
    sign_in_via_api

    delete "/api/v1/sessions"

    expect(response).to have_http_status(:unprocessable_entity)
    expect(JSON.parse(response.body)).to eq("error" => { "code" => "invalid_csrf_token", "message" => "Invalid or missing CSRF token" })

    get "/api/v1/sessions"
    expect(response).to have_http_status(:ok)
  end

  it "rejects delete with an invalid CSRF token" do
    sign_in_via_api

    delete "/api/v1/sessions", headers: { "X-CSRF-Token" => "forged" }

    expect(response).to have_http_status(:unprocessable_entity)
    expect(JSON.parse(response.body).fetch("error").fetch("code")).to eq("invalid_csrf_token")
  end
end
