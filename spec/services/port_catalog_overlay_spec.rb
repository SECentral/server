require "rails_helper"

RSpec.describe PortCatalogOverlay do
  let(:identity) { "sha256:38ab88c50fc36df9b568ec4b7237b1693b9d0d3b64a3e9bc83f887fb9b6751f3" }
  let(:catalog) do
    {
      "policy_identity" => identity, "version" => "test", "provenance" => "test",
      "completeness" => { "tcp" => "complete", "udp" => "incomplete" },
      "mappings" => [
        { "type" => "http_port_t", "protocol" => "tcp", "start" => 80, "end" => 90 },
        { "type" => "http_port_t", "protocol" => "tcp", "start" => 8080, "end" => 8080 }
      ]
    }
  end

  before do
    allow(PortCatalog).to receive(:for).and_return(nil)
    allow(PortCatalog).to receive(:for).with(identity).and_return(catalog)
  end

  def host(id, mappings:, status: "observed", stale: false, identity: self.identity)
    details = { "selinux" => { "policy_identity" => identity, "policy" => { "port_inventory" => { "status" => status, "local_classification_status" => "observed", "mappings" => mappings } } } }
    observation = Struct.new(:host_snapshot, :stale?).new(Struct.new(:details).new(details), stale)
    Struct.new(:id, :hostname, :current_state_observation).new(id, "host-#{id}", observation)
  end

  def mapping(type, start_port, end_port = start_port, protocol: "tcp", provenance: "not_confirmed_custom")
    { "type" => type, "protocol" => protocol, "ports" => [{ "start" => start_port, "end" => end_port, "provenance" => provenance }] }
  end

  def segments(result)
    result.dig(:observed, :segments)
  end

  it "A-C: matches equivalent splits and reports a complete-inventory gap" do
    split = described_class.call(hosts: [host(1, mappings: [mapping("http_port_t", 80, 85), mapping("http_port_t", 86, 90)])], policy_identity: identity)
    expect(segments(split)).to include(include(start: 80, end: 90, relation: "matching_effective_type"))

    gap = described_class.call(hosts: [host(1, mappings: [mapping("http_port_t", 80, 89)])], policy_identity: identity)
    expect(segments(gap).map { |segment| [segment[:start], segment[:end], segment[:relation]] }).to include([90, 90, "catalog_defined_not_observed"])
  end

  it "D-F: preserves type differences and custom evidence" do
    different = described_class.call(hosts: [host(1, mappings: [mapping("http_port_t", 80, 85), mapping("other_port_t", 86, 90)])], policy_identity: identity)
    expect(segments(different)).to include(include(start: 86, end: 90, relation: "different_effective_type"))

    custom = described_class.call(hosts: [host(1, mappings: [mapping("http_port_t", 85, provenance: "custom")])], policy_identity: identity)
    expect(segments(custom)).to include(include(start: 85, end: 85, relation: "matching_effective_type", local_classification: "custom"))

    custom_different = described_class.call(hosts: [host(1, mappings: [mapping("other_port_t", 85, provenance: "custom")])], policy_identity: identity)
    expect(segments(custom_different)).to include(include(start: 85, end: 85, relation: "different_effective_type", local_classification: "custom"))
  end

  it "G-L: distinguishes complete/incomplete catalog protocols, partial evidence, protocol, and port 65535" do
    complete = described_class.call(hosts: [host(1, mappings: [mapping("other_port_t", 443)])], policy_identity: identity)
    expect(segments(complete)).to include(include(protocol: "tcp", start: 443, relation: "observed_not_represented"))

    incomplete = described_class.call(hosts: [host(1, mappings: [mapping("dns_port_t", 53, protocol: "udp")])], policy_identity: identity)
    expect(segments(incomplete)).to include(include(protocol: "udp", relation: "observed_not_represented_in_incomplete_catalog"))

    partial = described_class.call(hosts: [host(1, mappings: [mapping("http_port_t", 80, 89)], status: "partial")], policy_identity: identity)
    expect(segments(partial)).to include(include(start: 90, relation: "comparison_unknown"))

    boundary_catalog = { "policy_identity" => identity, "version" => "test", "provenance" => "test", "completeness" => { "tcp" => "complete" }, "mappings" => [{ "type" => "last_port_t", "protocol" => "tcp", "start" => 65535, "end" => 65535 }] }
    allow(PortCatalog).to receive(:for).with(identity).and_return(boundary_catalog)
    boundary = described_class.call(hosts: [host(1, mappings: [mapping("last_port_t", 65535)])], policy_identity: identity)
    expect(segments(boundary)).to include(include(start: 65535, end: 65535, relation: "matching_effective_type"))
  end

  it "M-O: classifies overlapping type sets by their actual difference" do
    ambiguous = described_class.call(hosts: [host(1, mappings: [mapping("http_port_t", 80, 90), mapping("other_port_t", 85, 85)])], policy_identity: identity)
    expect(segments(ambiguous)).to include(include(start: 85, end: 85, catalog_types: ["http_port_t"], observed_types: ["http_port_t", "other_port_t"], relation: "different_effective_type"))

    overlapping_catalog = { "policy_identity" => identity, "version" => "test", "provenance" => "test", "completeness" => { "tcp" => "complete" }, "mappings" => [{ "type" => "one_t", "protocol" => "tcp", "start" => 80, "end" => 90 }, { "type" => "two_t", "protocol" => "tcp", "start" => 85, "end" => 85 }] }
    allow(PortCatalog).to receive(:for).with(identity).and_return(overlapping_catalog)
    catalog_ambiguous = described_class.call(hosts: [host(1, mappings: [mapping("one_t", 80, 90)])], policy_identity: identity)
    expect(segments(catalog_ambiguous)).to include(include(start: 85, end: 85, catalog_types: ["one_t", "two_t"], observed_types: ["one_t"], relation: "different_effective_type"))
  end

  it "A-G: preserves observed-only evidence when the exact cohort has no catalog" do
    no_catalog = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    complete = host(1, identity: no_catalog, mappings: [mapping("http_port_t", 8080, provenance: "custom")])
    partial = host(2, identity: no_catalog, mappings: [mapping("my_app_port_t", 8081)], status: "partial")
    unavailable = host(3, identity: no_catalog, mappings: [], status: "unavailable")
    unknown = host(4, identity: no_catalog, mappings: [], status: "unknown")
    stale = host(5, identity: no_catalog, mappings: [mapping("http_port_t", 8082)], stale: true)
    result = described_class.call(hosts: [complete, partial, unavailable, unknown, stale], policy_identity: no_catalog)

    expect(result[:catalog]).to include(available: false)
    expect(result.dig(:observed, :segments)).to be_empty
    expect(result.dig(:observed, :observed_mappings)).to include(include(start: 8080, provenance: "custom", inventory_status: "observed"), include(start: 8081, inventory_status: "partial"))
    expect(result.dig(:observed, :stale_observed_mappings)).to include(include(start: 8082, inventory_status: "stale"))
    expect(result[:observed]).to include(unavailable_host_count: 1, unknown_host_count: 1)
  end
end
