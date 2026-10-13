require "rails_helper"

RSpec.describe "Operator authentication", type: :request do
  it "serves the SPA login page anonymously" do
    get "/login"

    expect(response).to have_http_status(:ok)
    expect(response.body).to include('<div id="root">')
  end

  it "logs in with valid credentials via the API" do
    post "/api/v1/sessions", params: { username: "test-admin", password: "test-password" }

    expect(response).to have_http_status(:created)
    expect(JSON.parse(response.body)).to eq("operator" => { "username" => "test-admin" })

    get "/api/v1/overview"
    expect(response).to have_http_status(:ok)
  end

  it "rejects invalid usernames and passwords with one generic error" do
    [
      { username: "wrong", password: "test-password" },
      { username: "test-admin", password: "wrong" }
    ].each do |credentials|
      post "/api/v1/sessions", params: credentials

      expect(response).to have_http_status(:unauthorized)
      expect(JSON.parse(response.body)).to eq("error" => { "code" => "unauthorized", "message" => "Invalid credentials" })
    end
  end

  it "fails closed when operator credentials are not configured" do
    username = ENV.delete("ADMIN_USERNAME")
    digest = ENV.delete("ADMIN_PASSWORD_DIGEST")

    post "/api/v1/sessions", params: { username: "test-admin", password: "test-password" }
    expect(response).to have_http_status(:unauthorized)
  ensure
    ENV["ADMIN_USERNAME"] = username
    ENV["ADMIN_PASSWORD_DIGEST"] = digest
  end

  it "returns 401 for anonymous protected JSON requests" do
    get "/api/v1/hosts/1"

    expect(response).to have_http_status(:unauthorized)
    expect(response.media_type).to eq("application/json")
  end

  it "allows authenticated operator JSON requests" do
    sign_in_operator
    get "/api/v1/hosts/1"

    expect(response).to have_http_status(:service_unavailable)
    expect(JSON.parse(response.body).dig("error", "code")).to eq("organization_unavailable")
  end

  it "does not let an operator session access agent endpoints" do
    sign_in_operator
    post "/api/v1/events", params: "{}", headers: { "CONTENT_TYPE" => "application/json" }
    expect(response).to have_http_status(:unauthorized)

    post "/api/v1/heartbeat", params: "{}", headers: { "CONTENT_TYPE" => "application/json" }
    expect(response).to have_http_status(:unauthorized)
  end

  it "does not let an ingestion key access operator endpoints" do
    get "/api/v1/catalogs", headers: { "Authorization" => "Bearer test-ingestion-key" }
    expect(response).to have_http_status(:unauthorized)
  end

  it "logs out and clears the operator session" do
    sign_in_operator

    delete "/api/v1/sessions"

    expect(response).to have_http_status(:no_content)
    get "/api/v1/overview"
    expect(response).to have_http_status(:unauthorized)
  end
end
