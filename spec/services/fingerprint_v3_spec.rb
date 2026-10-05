require "rails_helper"

RSpec.describe FingerprintV3 do
  let(:fixture) { JSON.parse(File.read(Rails.root.join("spec/fixtures/contracts/fingerprinting-v3.json"))) }

  it "matches every frozen fingerprint vector" do
    fixture.fetch("cases").each do |vector|
      result = described_class.call(
        source_type: vector.fetch("source_type"),
        target_type: vector.fetch("target_type"),
        target_class: vector.fetch("target_class"),
        permissions: vector.fetch("permissions")
      )

      expect(result[:status]).to eq("ok"), vector.fetch("name")
      expect(result[:canonical].unpack1("H*")).to eq(vector.fetch("canonical_hex")), vector.fetch("name")
      expect(result[:digest]).to eq(vector.fetch("sha256")), vector.fetch("name")
    end
  end

  it "ignores permission ordering and duplicates" do
    first = described_class.call(source_type: "httpd_t", target_type: "default_t", target_class: "file", permissions: %w[read open read])
    second = described_class.call(source_type: "httpd_t", target_type: "default_t", target_class: "file", permissions: %w[open read])

    expect(first[:digest]).to eq(second[:digest])
  end

  it "changes identity when the permission set changes" do
    single = described_class.call(source_type: "httpd_t", target_type: "default_t", target_class: "file", permissions: ["read"])
    multiple = described_class.call(source_type: "httpd_t", target_type: "default_t", target_class: "file", permissions: %w[open read])

    expect(single[:digest]).not_to eq(multiple[:digest])
  end

  it "returns an explicit result for missing required fields" do
    result = described_class.call(source_type: "httpd_t", target_type: "default_t", target_class: "file")

    expect(result).to eq(status: "ungroupable", missing: [:permissions])
  end
end
