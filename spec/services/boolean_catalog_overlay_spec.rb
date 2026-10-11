require "rails_helper"

RSpec.describe BooleanCatalogOverlay do
  let(:identity) { "sha256:38ab88c50fc36df9b568ec4b7237b1693b9d0d3b64a3e9bc83f887fb9b6751f3" }
  let(:other_identity) { "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
  let(:catalog) do
    {
      "policy_identity" => identity, "version" => "test", "provenance" => "test", "complete" => true,
      "booleans" => [
        { "name" => "httpd_can_network_connect", "default" => false, "description" => "Allow network" },
        { "name" => "httpd_enable_cgi", "default" => false, "description" => "Allow CGI" }
      ]
    }
  end

  before do
    allow(BooleanCatalog).to receive(:for).and_return(nil)
    allow(BooleanCatalog).to receive(:for).with(identity).and_return(catalog)
  end

  def host(details = nil, stale: false)
    observation = details && Struct.new(:host_snapshot, :stale?).new(Struct.new(:details).new(details), stale)
    Struct.new(:current_state_observation).new(observation)
  end

  def details(identity:, boolean_status: "observed", booleans: [])
    { "selinux" => { "policy_identity" => identity, "boolean_status" => boolean_status, "booleans" => booleans } }
  end

  def row(result, name = "httpd_can_network_connect")
    result.dig(:observed, :rows).find { |item| item[:name] == name }
  end

  it "A: keeps a catalog-default-Off boolean unknown when the host did not observe it" do
    result = described_class.call(hosts: [host(details(identity: identity))], policy_identity: identity)
    expect(row(result).dig(:counts, "unknown")).to eq(1)
    expect(row(result).dig(:counts, "off")).to eq(0)
  end

  it "B: keeps collection failure unavailable despite the catalog default" do
    result = described_class.call(hosts: [host(details(identity: identity, boolean_status: "unavailable"))], policy_identity: identity)
    expect(row(result).dig(:counts, "unavailable")).to eq(1)
    expect(row(result).dig(:counts, "off")).to eq(0)
  end

  it "does not upgrade an unrecognized collection status from retained observed entries" do
    result = described_class.call(hosts: [host(details(identity: identity, boolean_status: "unsupported", booleans: [{ "name" => "httpd_can_network_connect", "current" => false, "status" => "observed" }]))], policy_identity: identity)
    expect(row(result).dig(:counts).slice("unknown", "off", "reference_match")).to eq("unknown" => 1, "off" => 0, "reference_match" => 0)
  end

  it "C: keeps stale last-observed On out of current On coverage" do
    result = described_class.call(hosts: [host(details(identity: identity, booleans: [{ "name" => "httpd_can_network_connect", "current" => true, "status" => "observed" }]), stale: true)], policy_identity: identity)
    expect(row(result).dig(:counts).slice("on", "stale")).to eq("on" => 0, "stale" => 1)
  end

  it "D and E: excludes no-heartbeat and event-only snapshots from cohort state" do
    result = described_class.call(hosts: [host, host], policy_identity: identity)
    expect(result.dig(:observed, :fresh_host_count)).to eq(0)
    expect(result.dig(:observed, :no_current_configuration_host_count)).to eq(2)
  end

  it "F and G: compares only exact cohort identities and preserves observed On and Off" do
    hosts = [
      host(details(identity: identity, booleans: [{ "name" => "httpd_can_network_connect", "current" => true, "status" => "observed" }])),
      host(details(identity: identity, booleans: [{ "name" => "httpd_can_network_connect", "current" => false, "status" => "observed" }])),
      host(details(identity: other_identity, booleans: [{ "name" => "httpd_can_network_connect", "current" => true, "status" => "observed" }]))
    ]
    result = described_class.call(hosts: hosts, policy_identity: identity)
    expect(result.dig(:observed, :fresh_host_count)).to eq(2)
    expect(result.dig(:observed, :rows).map { |item| item[:name] }).to eq(%w[httpd_can_network_connect httpd_enable_cgi])
    expect(row(result).dig(:counts).slice("on", "off")).to eq("on" => 1, "off" => 1)
  end

  it "H: marks complete-catalog unmatched observations conservatively" do
    result = described_class.call(hosts: [host(details(identity: identity, booleans: [{ "name" => "unlisted_boolean", "current" => true, "status" => "observed" }]))], policy_identity: identity, catalog: catalog)
    expect(row(result, "unlisted_boolean").slice(:catalog, :catalog_status)).to eq(catalog: nil, catalog_status: "not_defined")
  end

  it "I: exposes a missing catalog without losing observations" do
    result = described_class.call(hosts: [host(details(identity: other_identity, booleans: [{ "name" => "unlisted_boolean", "current" => false, "status" => "observed" }]))], policy_identity: other_identity)
    expect(result[:catalog]).to include(available: false, completeness: "unavailable")
    expect(row(result, "unlisted_boolean").dig(:counts, "off")).to eq(1)
  end

  it "J: does not call an unmatched item undefined when the catalog is incomplete" do
    incomplete = { "policy_identity" => identity, "version" => "test", "provenance" => "test", "complete" => false, "booleans" => [] }
    result = described_class.call(hosts: [host(details(identity: identity, booleans: [{ "name" => "unlisted_boolean", "current" => true, "status" => "observed" }]))], policy_identity: identity, catalog: incomplete)
    expect(row(result, "unlisted_boolean")[:catalog_status]).to eq("not_represented")
  end
end
