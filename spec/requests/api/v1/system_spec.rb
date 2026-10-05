require "rails_helper"

RSpec.describe "API v1 system", type: :request do
  it "requires authentication" do
    get "/api/v1/system"

    expect(response).to have_http_status(:unauthorized)
  end

  it "reports the api version, server version, and capabilities" do
    sign_in_operator

    get "/api/v1/system"

    expect(response).to have_http_status(:ok)
    body = JSON.parse(response.body)
    expect(body).to include("api_version" => "v1")
    expect(body.fetch("server_version")).to eq(File.read(Rails.root.join("VERSION")).strip)
    expect(body.fetch("server_version")).to match(/\A\d+\.\d+\.\d+\z/)
    expect(body.fetch("capabilities")).to include("issue-diagnosis", "distribution-catalogs")
  end
end
