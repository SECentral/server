require "rails_helper"

RSpec.describe FileContextMatcher do
  it "matches complete paths against fcontext patterns" do
    result = described_class.call("/var/www/index.html", [
      { "pattern" => "/var/www(/.*)?", "context" => "system_u:object_r:httpd_sys_content_t:s0" },
      { "pattern" => "/srv(/.*)?", "context" => "system_u:object_r:var_t:s0" }
    ])

    expect(result[:matches].map { |mapping| mapping["context"] }).to eq(["system_u:object_r:httpd_sys_content_t:s0"])
    expect(result[:invalid_patterns]).to be_empty
  end

  it "preserves ambiguous matches and reports invalid patterns" do
    result = described_class.call("/var/www/index.html", [
      { "pattern" => "/var/www(/.*)?", "context" => "one" },
      { "pattern" => "/var/.*", "context" => "two" },
      { "pattern" => "[", "context" => "invalid" }
    ])

    expect(result[:matches].size).to eq(2)
    expect(result[:invalid_patterns]).to eq(["["])
  end
end
