require "rails_helper"

RSpec.describe DistributionCatalogArtifact do
  def document
    JSON.parse(File.read(Rails.root.join("spec/fixtures/catalogs/v4.json")))
  end

  def artifact(value = document)
    described_class.new(JSON.generate(value))
  end

  it "reproduces the Go V4 populated and empty canonical bytes and digests" do
    vector = JSON.parse(File.read(Rails.root.join("spec/fixtures/contracts/catalog-canonicalization-v4.json")))

    expect(DistributionCatalogCanonicalizer.call(document.fetch("catalog"))).to eq(vector.fetch("canonical_json"))
    expect(artifact.validate!.content_digest).to eq(vector.fetch("content_digest"))
    empty = document
    empty.dig("catalog", "families", "effective_permissive_domains")["domains"] = []
    empty["content_digest"] = vector.fetch("empty_content_digest")
    expect(DistributionCatalogCanonicalizer.call(empty.fetch("catalog"))).to eq(vector.fetch("canonical_json").sub('["example_t"]', '[]'))
    expect(artifact(empty).validate!.content_digest).to eq(vector.fetch("empty_content_digest"))
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
    "v3 semantics" => ->(value) { value.dig("catalog")["collector_semantics_version"] = 3 },
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

  it "accepts overlapping mappings because the port contract permits them" do
    value = document
    value.dig("catalog", "families", "ports", "mappings") << { "type" => "other_port_t", "protocol" => "tcp", "start" => 80, "end" => 80 }
    value.dig("catalog", "families", "ports", "mappings").sort_by! { |mapping| [mapping["protocol"], mapping["start"], mapping["end"], mapping["type"]] }
    value["content_digest"] = "sha256:#{Digest::SHA256.hexdigest(DistributionCatalogCanonicalizer.call(value.fetch("catalog")))}"

    expect(artifact(value).validate!).to be_a(described_class)
  end

  it "rejects duplicate JSON object keys instead of silently replacing evidence" do
    raw = JSON.generate(document).sub('"schema_version":1', '"schema_version":1,"schema_version":1')
    expect { described_class.new(raw).validate! }.to raise_error(described_class::Invalid) { |error| expect(error.code).to eq("malformed_json") }
  end

  {
    "missing family" => ->(family) { family.clear },
    "incomplete" => ->(family) { family["complete"] = false },
    "missing domains" => ->(family) { family.delete("domains") },
    "null domains" => ->(family) { family["domains"] = nil },
    "invalid domain" => ->(family) { family["domains"] = ["bad-name"] },
    "non-string domain" => ->(family) { family["domains"] = [nil] },
    "duplicate domains" => ->(family) { family["domains"] = %w[a_t a_t] },
    "unsorted domains" => ->(family) { family["domains"] = %w[z_t a_t] },
    "unsupported semantics" => ->(family) { family["extractor_semantics_version"] = 2 },
    "fractional semantics" => ->(family) { family["extractor_semantics_version"] = 1.0 },
    "missing tool" => ->(family) { family["evaluator_version"] = nil },
    "empty tool version" => ->(family) { family["evaluator_version"] = "SETools " },
    "control in tool version" => ->(family) { family["evaluator_version"] = "SETools 4\n" },
    "oversized tool version" => ->(family) { family["evaluator_version"] = "SETools " + "x" * 120 }
  }.each do |name, mutate|
    it "rejects #{name} in the inline permissive family before digest verification" do
      value = document
      mutate.call(value.dig("catalog", "families", "effective_permissive_domains"))
      value["content_digest"] = "sha256:" + "0" * 64
      expect { artifact(value).validate! }.to raise_error(described_class::Invalid) { |error| expect(error.code).to eq("invalid_permissive_domain_family") }
    end
  end

  it "detects tampered inline membership without a new content digest" do
    value = document
    value.dig("catalog", "families", "effective_permissive_domains")["domains"] = ["other_t"]
    expect { artifact(value).validate! }.to raise_error(described_class::Invalid) { |error| expect(error.code).to eq("digest_mismatch") }
  end

  it "explicitly rejects original semantics 3 artifacts" do
    raw = File.binread(Rails.root.join("spec/fixtures/catalogs/v3.json"))
    expect { described_class.new(raw).validate! }.to raise_error(described_class::Invalid) { |error| expect(error.code).to eq("unsupported_collector_semantics") }
  end
end
