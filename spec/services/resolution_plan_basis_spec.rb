require "rails_helper"

RSpec.describe ResolutionPlanBasis do
  it "canonicalizes nested key order and symbol/string keys across database serialization" do
    first = { scope: { host: 1, kind: "file" }, steps: [{ command: "inspect", persistence: "inspection" }] }
    second = { "steps" => [{ "persistence" => "inspection", "command" => "inspect" }], "scope" => { "kind" => "file", "host" => 1 } }
    expect(described_class.digest(first)).to eq(described_class.digest(second))
  end

  it "preserves meaningful command order while permitting explicitly unordered evidence sets" do
    steps = [{ command: "inspect" }, { command: "apply" }]
    expect(described_class.digest(steps)).not_to eq(described_class.digest(steps.reverse))
    expect(described_class.ordered_set(steps)).to eq(described_class.ordered_set(steps.reverse))
  end
end
