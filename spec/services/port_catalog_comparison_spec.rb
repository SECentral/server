require "rails_helper"

RSpec.describe PortCatalogComparison do
  def mapping(type, start_port, end_port = start_port, protocol: "tcp", provenance: "not_confirmed_custom")
    { type: type, protocol: protocol, start: start_port, end: end_port, provenance: provenance }
  end

  it "compares canonical equivalent ranges without host orchestration" do
    result = described_class.call(
      catalog_mappings: [mapping("http_port_t", 80, 90)],
      catalog_completeness: { "tcp" => "complete" },
      inventory_status: "observed",
      observed_mappings: [mapping("http_port_t", 80, 85), mapping("http_port_t", 86, 90)]
    )

    expect(result).to contain_exactly(include(protocol: "tcp", start: 80, end: 90, relation: "matching_effective_type", inventory_status: "observed"))
  end

  it "preserves partial inventory and local provenance semantics" do
    result = described_class.call(
      catalog_mappings: [mapping("http_port_t", 80, 90)],
      catalog_completeness: { "tcp" => "complete" },
      inventory_status: "partial",
      observed_mappings: [mapping("http_port_t", 80, 84), mapping("other_port_t", 85, provenance: "custom"), mapping("http_port_t", 86, 89)]
    )

    expect(result).to include(include(start: 85, end: 85, relation: "different_effective_type", local_classification: "custom"), include(start: 90, end: 90, relation: "comparison_unknown"))
  end

  it "does not make absence claims for unavailable or unknown inventories" do
    ["unavailable", "unknown", nil, "unsupported"].each do |status|
      result = described_class.call(
        catalog_mappings: [mapping("http_port_t", 80)],
        catalog_completeness: { "tcp" => "complete" },
        inventory_status: status,
        observed_mappings: [mapping("http_port_t", 80)]
      )

      expect(result).to be_empty
    end
  end

  it "matches multi-type segments when catalog and host type sets agree" do
    result = described_class.call(
      catalog_mappings: [mapping("reserved_port_t", 1, 1024), mapping("ssh_port_t", 22)],
      catalog_completeness: { "tcp" => "complete" },
      inventory_status: "observed",
      observed_mappings: [mapping("reserved_port_t", 1, 1024), mapping("ssh_port_t", 22)]
    )

    expect(result).to include(include(start: 22, end: 22, catalog_types: ["reserved_port_t", "ssh_port_t"], observed_types: ["reserved_port_t", "ssh_port_t"], relation: "matching_effective_type"))
  end

  it "marks divergent multi-type segments as different effective types" do
    result = described_class.call(
      catalog_mappings: [mapping("reserved_port_t", 1, 1024), mapping("ssh_port_t", 22)],
      catalog_completeness: { "tcp" => "complete" },
      inventory_status: "observed",
      observed_mappings: [mapping("reserved_port_t", 1, 1024), mapping("my_app_port_t", 22, provenance: "custom")]
    )

    expect(result).to include(include(start: 22, end: 22, catalog_types: ["reserved_port_t", "ssh_port_t"], observed_types: ["my_app_port_t", "reserved_port_t"], relation: "different_effective_type"))
  end

  it "keeps explicit local evidence when a custom range overlaps a base-policy range" do
    result = described_class.call(
      catalog_mappings: [mapping("unreserved_port_t", 1024, 65535)],
      catalog_completeness: { "tcp" => "complete" },
      inventory_status: "observed",
      observed_mappings: [mapping("unreserved_port_t", 1024, 65535), mapping("http_port_t", 8888, provenance: "custom")]
    )

    expect(result).to include(include(start: 8888, end: 8888, catalog_types: ["unreserved_port_t"], observed_types: ["http_port_t", "unreserved_port_t"], relation: "different_effective_type", local_classification: "custom"))
  end
end
