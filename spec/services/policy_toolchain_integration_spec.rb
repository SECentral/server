require "rails_helper"

RSpec.describe "Policy toolchain integration" do
  it "extracts the rules and permissive types from a valid binary policy" do
    bytes = File.binread(Rails.root.join("spec/fixtures/policies/minimal.policy"))
    identity = "sha256:#{Digest::SHA256.hexdigest(bytes)}"
    artifact = instance_double(PolicyArtifact, artifact: bytes, policy_identity: identity)
    fact = instance_double(PolicyFact, policy_identity: identity, query_kind: PolicyFact::QUERY_KIND,
      source_type: "source_t", target_type: "target_t", object_class: "file", permission: "read")

    result = PolicyRuleEvaluator.call(fact, artifact)
    expect(result).to include(status: "matched", matching_rules: ["allow source_t target_t:file read;"])
    expect(result[:rule_details]).to include(include("source_symbol" => "source_t", "target_symbol" => "target_t", "permissions" => ["read"]))
    allow(fact).to receive(:permission).and_return("write")
    expect(PolicyRuleEvaluator.call(fact, artifact)).to include(status: "no_match", matching_rules: [])
    expect(PolicyPermissiveDomainAnalyzer.call(artifact)).to include("status" => "observed", "domains" => ["permissive_t"], "evaluator_version" => "SETools 4.6.0")
  end
end
