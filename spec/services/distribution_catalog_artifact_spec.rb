require "rails_helper"

RSpec.describe DistributionCatalogArtifact do
  def document
    JSON.parse(File.read(Rails.root.join("spec/fixtures/catalogs/v3.json")))
  end

  def artifact(value = document)
    described_class.new(JSON.generate(value))
  end

  it "reproduces the Go V3 golden canonical bytes and digest" do
    vector = JSON.parse(File.read(Rails.root.join("spec/fixtures/contracts/catalog-canonicalization-v3.json")))

    expect(DistributionCatalogCanonicalizer.call(vector.fetch("catalog"))).to eq(vector.fetch("canonical_json"))
    expect(Digest::SHA256.hexdigest(vector.fetch("canonical_json"))).to eq("3d8dff7fdef145ff2b0db34036d55248e97e6b33c231e5f6fe04d2ec19d3131d")
    expect(artifact.validate!.content_digest).to eq(vector.fetch("content_digest"))
  end

  it "keeps semantic identity independent of object order and acquisition metadata" do
    first = document
    second = { "metadata" => first.fetch("metadata").merge("source" => "other"), "catalog" => first.fetch("catalog"), "content_digest" => first.fetch("content_digest"), "schema_version" => 1 }

    expect(artifact(first).validate!.content_digest).to eq(artifact(second).validate!.content_digest)
  end

  it "changes identity when semantic catalog content changes" do
    first = artifact.validate!.content_digest
    changed = document
    changed.dig("catalog", "families", "booleans", "entries", 0)["description"] = "Changed"
    changed["content_digest"] = "sha256:#{Digest::SHA256.hexdigest(DistributionCatalogCanonicalizer.call(changed.fetch("catalog")))}"

    expect(artifact(changed).validate!.content_digest).not_to eq(first)
  end

  {
    "schema" => ->(value) { value["schema_version"] = 2 },
    "non-integer schema" => ->(value) { value["schema_version"] = 1.0 },
    "non-integer collector semantics" => ->(value) { value["catalog"]["collector_semantics_version"] = 3.0 },
    "v1 semantics" => ->(value) { value.dig("catalog")["collector_semantics_version"] = 1 },
    "v2 semantics" => ->(value) { value.dig("catalog")["collector_semantics_version"] = 2 },
    "digest" => ->(value) { value["content_digest"] = "sha256:" + "0" * 64 },
    "policy digest" => ->(value) { value.dig("catalog", "policy")["loaded_policy_digest"] = "invalid" },
    "incomplete boolean family" => ->(value) { value.dig("catalog", "families", "booleans")["complete"] = false },
    "duplicate boolean" => ->(value) { value.dig("catalog", "families", "booleans", "entries") << value.dig("catalog", "families", "booleans", "entries").first.deep_dup },
    "noncanonical booleans" => ->(value) { value.dig("catalog", "families", "booleans", "entries").reverse! },
    "invalid protocol" => ->(value) { value.dig("catalog", "families", "ports", "mappings", 0)["protocol"] = "icmp" },
    "invalid port range" => ->(value) { value.dig("catalog", "families", "ports", "mappings", 0)["end"] = 65_536 },
    "duplicate port" => ->(value) { value.dig("catalog", "families", "ports", "mappings") << value.dig("catalog", "families", "ports", "mappings").first.deep_dup },
    "noncanonical ports" => ->(value) { value.dig("catalog", "families", "ports", "mappings").reverse! }
  }.each do |name, mutate|
    it "rejects #{name}" do
      value = document
      mutate.call(value)

      expect { artifact(value).validate! }.to raise_error(DistributionCatalogArtifact::Invalid)
    end
  end

  it "accepts overlapping mappings because the V3 port contract permits them" do
    value = document
    value.dig("catalog", "families", "ports", "mappings") << { "type" => "other_port_t", "protocol" => "tcp", "start" => 80, "end" => 80 }
    value.dig("catalog", "families", "ports", "mappings").sort_by! { |mapping| [mapping["protocol"], mapping["start"], mapping["end"], mapping["type"]] }
    value["content_digest"] = "sha256:#{Digest::SHA256.hexdigest(DistributionCatalogCanonicalizer.call(value.fetch("catalog")))}"

    expect(artifact(value).validate!).to be_a(described_class)
  end
end
