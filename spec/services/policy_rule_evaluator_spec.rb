require "rails_helper"

RSpec.describe PolicyRuleEvaluator do
  let(:bytes) { "policy bytes" }
  let(:identity) { "sha256:#{Digest::SHA256.hexdigest(bytes)}" }
  let(:fact) do
    instance_double(PolicyFact, query_kind: PolicyFact::QUERY_KIND, policy_identity: identity, source_type: "httpd_t", target_type: "unreserved_port_t",
      object_class: "tcp_socket", permission: "name_connect")
  end
  let(:artifact) { instance_double(PolicyArtifact, artifact: bytes) }
  let(:success) { instance_double(Process::Status, success?: true, exitstatus: 0) }

  it "preserves attribute-derived rules, conditional expression, and branch" do
    output = "allow nsswitch_domain unreserved_port_t:tcp_socket name_connect; [ nis_enabled ]:True\n"
    allow(SetoolsProcess).to receive(:call).with("sesearch", "--version").and_return([ "4.4.4\n", "", success ])
    allow(SetoolsProcess).to receive(:call).with("sesearch", "--allow", any_args).and_return([ output, "", success ])

    result = described_class.call(fact, artifact)

    expect(result).to include(status: "matched", evaluator_version: "4.4.4")
    expect(result[:rule_details].first).to include(
      "source_symbol" => "nsswitch_domain", "source_match" => "attribute",
      "conditional_expression" => "nis_enabled", "conditional_branch" => "True"
    )
  end

  it "keeps successful empty output distinct from evaluator errors and unavailability" do
    allow(SetoolsProcess).to receive(:call).with("sesearch", "--version").and_return([ "4.4.4\n", "", success ])
    allow(SetoolsProcess).to receive(:call).with("sesearch", "--allow", any_args).and_return([ "", "", success ])
    expect(described_class.call(fact, artifact)).to include(status: "no_match")

    allow(SetoolsProcess).to receive(:call).with("sesearch", "--allow", any_args).and_return([ "progress is not an allow rule", "", success ])
    expect(described_class.call(fact, artifact)).to include(status: "error")

    allow(SetoolsProcess).to receive(:call).with("sesearch", "--allow", any_args).and_return([ "", "invalid policy", instance_double(Process::Status, success?: false, exitstatus: 1) ])
    expect(described_class.call(fact, artifact)).to include(status: "error")

    allow(SetoolsProcess).to receive(:call).with("sesearch", "--allow", any_args).and_raise(StandardError, "runtime bound")
    expect(described_class.call(fact, artifact)).to include(status: "error")

    allow(SetoolsProcess).to receive(:call).with("sesearch", "--version").and_raise(Errno::ENOENT)
    expect(described_class.call(fact, artifact)).to include(status: "unavailable")
  end

  it "rejects artifact bytes that do not match the requested identity" do
    wrong = instance_double(PolicyArtifact, artifact: "other bytes")

    expect(described_class.call(fact, wrong)).to include(status: "unavailable", error_message: "policy artifact identity mismatch")
  end

  it "retains expanded port target types and conditions from the bounded exact-policy query" do
    allow(fact).to receive_messages(query_kind: PolicyFact::PORT_QUERY_KIND, target_type: "port_type")
    rule = "allow httpd_t web_ports:tcp_socket name_connect; [ feature_enabled ]:True"
    output = { "evaluator_version" => "SETools test", "rules" => [{ "rule" => rule, "target_types" => %w[http_port_t http_cache_port_t] }], "port_contexts" => [] }.to_json
    expect(SetoolsProcess).to receive(:call).with("python3", Rails.root.join("script/policy_port_allows.py").to_s,
      kind_of(String), "httpd_t", "tcp_socket", "name_connect").and_return([output, "", success])
    result = described_class.call(fact, artifact)
    expect(result[:status]).to eq("matched")
    expect(result[:rule_details].first).to include("target_types" => %w[http_cache_port_t http_port_t], "conditional_expression" => "feature_enabled")
    expect(result[:rule_details].last).to include("kind" => "port_contexts", "mappings" => [])
  end

  it "rejects malformed expanded types and mismatched permission evidence" do
    allow(fact).to receive_messages(query_kind: PolicyFact::PORT_QUERY_KIND, target_type: "port_type")
    ["allow httpd_t http_port_t:tcp_socket name_bind;", "not a rule"].each do |rule|
      allow(SetoolsProcess).to receive(:call).and_return([{ "evaluator_version" => "test", "rules" => [{ "rule" => rule, "target_types" => ["http_port_t"] }] }.to_json, "", success])
      expect(described_class.call(fact, artifact)[:status]).to eq("error")
    end
    allow(SetoolsProcess).to receive(:call).and_return([{ "evaluator_version" => "test", "rules" => [{ "rule" => "allow httpd_t http_port_t:tcp_socket name_connect;", "target_types" => ["bad;command"] }] }.to_json, "", success])
    expect(described_class.call(fact, artifact)[:status]).to eq("error")
    allow(SetoolsProcess).to receive(:call).and_return([{ "evaluator_version" => "test", "rules" => [],
      "port_contexts" => [{ "type" => 1, "start" => 80, "end" => 80 }] }.to_json, "", success])
    expect(described_class.call(fact, artifact)[:status]).to eq("error")
  end
end
