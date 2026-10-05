require "rails_helper"

RSpec.describe "SPA serving", type: :request do
  def serve_fixture_spa
    allow(SpaController).to receive(:index_file).and_return(Rails.root.join("spec/fixtures/spa/index.html"))
  end

  it "serves the SPA shell for application routes without authentication" do
    serve_fixture_spa

    get "/issues"

    expect(response).to have_http_status(:ok)
    expect(response.headers["Cache-Control"]).to eq("no-store")
    expect(response.body).to include('<div id="root">')
  end

  it "returns 503 when the SPA build is missing" do
    allow(SpaController).to receive(:index_file).and_return(Rails.root.join("spec/fixtures/spa/missing.html"))

    get "/issues"

    expect(response).to have_http_status(:service_unavailable)
    expect(response.body).to include("npm run build")
  end

  it "does not shadow the API or the health check" do
    get "/api/v1/system"
    expect(response).to have_http_status(:unauthorized)

    get "/up"
    expect(response).to have_http_status(:ok)
  end

  it "does not route retired dashboard screens" do
    get "/dashboard/servers"

    expect(response).to have_http_status(:not_found)
  end
end
