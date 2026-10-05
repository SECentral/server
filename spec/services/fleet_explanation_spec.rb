require "rails_helper"

RSpec.describe FleetExplanation do
  def agreed(id, signature = { kind: "conditional_allow_inactive" })
    { host_id: id, hostname: "host-#{id}", status: "agreement", diagnosis: { kind: signature[:kind], title: signature[:kind].to_s.humanize }, occurrence_diagnoses: [{ occurrence_id: id, agreement_signature: signature }] }
  end

  def insufficient(id)
    { host_id: id, hostname: "host-#{id}", status: "insufficient_evidence", diagnosis: nil, occurrence_diagnoses: [{ occurrence_id: id, diagnosis: nil }] }
  end

  def disagreeing(id)
    { host_id: id, hostname: "host-#{id}", status: "disagreement", diagnosis: nil, occurrence_diagnoses: [{ occurrence_id: id, diagnosis: { kind: "conditional_allow_inactive" } }, { occurrence_id: id + 100, diagnosis: { kind: "no_matching_allow" } }] }
  end

  it "is consistent when all hosts share one signature" do
    result = described_class.call([agreed(1), agreed(2)])

    expect(result).to include(state: "consistent", affected_host_count: 2, host_status_counts: { "agreement" => 2 })
    expect(result[:explanation_groups].first[:hosts].map { |host| host[:host_id] }).to contain_exactly(1, 2)
  end

  it "is disagreement when two agreed hosts differ" do
    expect(described_class.call([agreed(1), agreed(2, { kind: "no_matching_allow" })])).to include(state: "disagreement")
  end

  it "does not let a majority override one conflicting host" do
    result = described_class.call([agreed(1), agreed(2), agreed(3, { kind: "no_matching_allow" })])

    expect(result).to include(state: "disagreement")
    expect(result[:explanation_groups].size).to eq(2)
  end

  it "is disagreement when a host has within-host disagreement" do
    result = described_class.call([agreed(1), disagreeing(2)])

    expect(result).to include(state: "disagreement")
    expect(result[:disagreeing_hosts]).to include(host_id: 2, hostname: "host-2")
  end

  it "is partially explained when agreed and insufficient hosts coexist" do
    result = described_class.call([agreed(1), insufficient(2)])

    expect(result).to include(state: "partially_explained")
    expect(result[:insufficient_evidence_hosts]).to include(include(host_id: 2))
  end

  it "is disagreement when explained hosts differ even with insufficient evidence" do
    expect(described_class.call([agreed(1), agreed(2, { kind: "no_matching_allow" }), insufficient(3)])).to include(state: "disagreement")
  end

  it "is insufficient when every host lacks a safe explanation" do
    expect(described_class.call([insufficient(1), insufficient(2)])).to include(state: "insufficient_evidence")
  end

  it "is consistent for one agreed host" do
    expect(described_class.call([agreed(1)])).to include(state: "consistent", affected_host_count: 1)
  end

  it "is insufficient for one unexplained host" do
    expect(described_class.call([insufficient(1)])).to include(state: "insufficient_evidence", affected_host_count: 1)
  end
end
