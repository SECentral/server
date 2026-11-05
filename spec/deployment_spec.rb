require "spec_helper"
require "yaml"

RSpec.describe "Compose MCP deployment" do
  let(:root) { File.expand_path("..", __dir__) }
  let(:services) { YAML.load_file(File.join(root, "compose.yaml")).fetch("services") }

  it "keeps MCP opt-in and derives exposure settings from the public domain" do
    environment = services.fetch("server").fetch("environment")
    expect(environment.fetch("SECENTRAL_MCP_AUTH_TOKEN")).to eq("${SECENTRAL_MCP_AUTH_TOKEN:-}")
    expect(environment.fetch("SECENTRAL_MCP_ALLOWED_HOSTS")).to start_with("${DOMAIN:?")
    expect(environment.fetch("SECENTRAL_MCP_PUBLIC_ORIGIN")).to eq("https://#{environment.fetch('SECENTRAL_MCP_ALLOWED_HOSTS')}")
    expect(environment.fetch("SECENTRAL_MCP_TRUSTED_PROXIES")).to eq("caddy")
    expect(services.fetch("server")).not_to have_key("ports")
  end

  it "routes only MCP directly to Puma and replaces forwarded HTTPS claims" do
    caddy = File.read(File.join(root, "Caddyfile"))
    expect(caddy).to include("@mcp path /mcp /mcp/*", "handle @mcp", "reverse_proxy server:3000",
      "header_up X-Forwarded-Proto {scheme}", "max_size 16384", "response_header_timeout 15s",
      "reverse_proxy server:80")
  end
end
