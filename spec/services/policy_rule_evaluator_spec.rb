require "rails_helper"

RSpec.describe PolicyRuleEvaluator do
  let(:bytes) { "policy bytes" }
  let(:identity) { "sha256:#{Digest::SHA256.hexdigest(bytes)}" }
  let(:fact) do
    instance_double(PolicyFact, policy_identity: identity, source_type: "httpd_t", target_type: "unreserved_port_t",
      object_class: "tcp_socket", permission: "name_connect")
  end
  let(:artifact) { instance_double(PolicyArtifact, artifact: bytes) }
  let(:success) { instance_double(Process::Status, success?: true, exitstatus: 0) }

  it "preserves attribute-derived rules, conditional expression, and branch" do
    output = "allow nsswitch_domain unreserved_port_t:tcp_socket name_connect; [ nis_enabled ]:True\n"
    allow(Open3).to receive(:capture2).and_return([ "4.4.4\n", success ])
    allow(Open3).to receive(:capture3).and_return([ output, "", success ])

    result = described_class.call(fact, artifact)

    expect(result).to include(status: "matched", evaluator_version: "4.4.4")
    expect(result[:rule_details].first).to include(
      "source_symbol" => "nsswitch_domain", "source_match" => "attribute",
      "conditional_expression" => "nis_enabled", "conditional_branch" => "True"
    )
  end

  it "keeps successful empty output distinct from evaluator errors and unavailability" do
    allow(Open3).to receive(:capture2).and_return([ "4.4.4\n", success ])
    allow(Open3).to receive(:capture3).and_return([ "", "", success ])
    expect(described_class.call(fact, artifact)).to include(status: "no_match")

    allow(Open3).to receive(:capture3).and_return([ "", "invalid policy", instance_double(Process::Status, success?: false, exitstatus: 1) ])
    expect(described_class.call(fact, artifact)).to include(status: "error")

    allow(Open3).to receive(:capture3).and_raise(Timeout::Error)
    expect(described_class.call(fact, artifact)).to include(status: "error")

    allow(Open3).to receive(:capture2).and_raise(Errno::ENOENT)
    expect(described_class.call(fact, artifact)).to include(status: "unavailable")
  end

  it "rejects artifact bytes that do not match the requested identity" do
    wrong = instance_double(PolicyArtifact, artifact: "other bytes")

    expect(described_class.call(fact, wrong)).to include(status: "unavailable", error_message: "policy artifact identity mismatch")
  end
end
