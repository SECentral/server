require "rails_helper"

RSpec.describe McpEndpoint::Admission do
  it "limits concurrent requests independently from the token bucket" do
    gate = described_class.new(clock: -> { 0.0 })
    expect(gate.acquire).to be_nil
    expect(gate.acquire).to be_nil
    expect(gate.acquire).to eq(1)
    gate.release
    expect(gate.acquire).to be_nil
  end

  it "has burst five, refills at 30 per minute, and has bounded state" do
    now = 0.0
    gate = described_class.new(clock: -> { now })
    5.times do
      expect(gate.acquire).to be_nil
      gate.release
    end
    expect(gate.acquire).to eq(2)
    now = 1.0
    expect(gate.acquire).to eq(1)
    now = 2.0
    expect(gate.acquire).to be_nil
    gate.release
    now = 600.0
    5.times do
      expect(gate.acquire).to be_nil
      gate.release
    end
    expect(gate.acquire).to eq(2)
  end
end
