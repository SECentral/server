require "rails_helper"

RSpec.describe "Security headers", type: :request do
  # Extracts the value of a single directive without depending on the order of
  # directives, so harmless reordering of the header does not break the specs.
  def directive_value(header, name)
    header.to_s.match(/(?:^|\s)#{Regexp.escape(name)}\s+([^;]+)/)&.captures&.first&.strip
  end

  def assert_restrictive_csp
    csp = response.headers["Content-Security-Policy"]
    expect(csp).to be_present

    expect(directive_value(csp, "default-src")).to eq("'self'")
    expect(directive_value(csp, "base-uri")).to eq("'self'")
    expect(directive_value(csp, "object-src")).to eq("'none'")
    expect(directive_value(csp, "frame-ancestors")).to eq("'none'")
    expect(directive_value(csp, "form-action")).to eq("'self'")
    expect(directive_value(csp, "script-src")).to eq("'self'")
    expect(directive_value(csp, "style-src")).to eq("'self'")
    expect(directive_value(csp, "img-src")).to eq("'self'")
    expect(directive_value(csp, "font-src")).to eq("'self'")
    expect(directive_value(csp, "connect-src")).to eq("'self'")

    # No dangerous sources may have crept in.
    expect(csp).not_to include("unsafe-inline")
    expect(csp).not_to include("unsafe-eval")
    expect(csp).not_to include("data:")
    expect(csp).not_to match(%r{https?://})
  end

  def assert_restrictive_permissions_policy
    pp = response.headers["Permissions-Policy"]
    expect(pp).to be_present

    # SECentral uses none of these browser features; each must be disabled.
    %w[camera microphone geolocation fullscreen payment usb autoplay
       display-capture encrypted-media picture-in-picture accelerometer gyroscope].each do |feature|
      expect(directive_value(pp, feature)).to eq("'none'")
    end
  end

  it "sends restrictive headers on an unauthenticated HTML response and the SPA login page renders" do
    get "/login"

    expect(response).to have_http_status(:ok)
    expect(response.body).to include('<div id="root">')
    assert_restrictive_csp
    assert_restrictive_permissions_policy
  end

  it "sends restrictive headers on the SPA shell" do
    sign_in_operator

    get "/"
    expect(response).to have_http_status(:ok)
    expect(response.body).to include('<div id="root">')
    assert_restrictive_csp
    assert_restrictive_permissions_policy
  end

  it "sends restrictive headers on the SPA shell and API responses" do
    allow(SpaController).to receive(:index_file).and_return(Rails.root.join("spec/fixtures/spa/index.html"))

    get "/issues"
    expect(response).to have_http_status(:ok)
    assert_restrictive_csp
    assert_restrictive_permissions_policy

    sign_in_operator

    get "/api/v1/system"
    expect(response).to have_http_status(:ok)
    assert_restrictive_csp
  end

  it "uses the current Permissions-Policy header, not the obsolete Feature-Policy" do
    get "/login"

    expect(response.headers["Permissions-Policy"]).to be_present
    expect(response.headers["Feature-Policy"]).to be_nil
  end
end
