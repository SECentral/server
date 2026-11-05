require "rails_helper"

RSpec.describe AgentInstallation, type: :model do
  it "uses reporting, stale, and offline boundaries based on heartbeat age" do
    now = Time.utc(2026, 11, 5)
    installation = described_class.new(last_seen_at: now - 1.second)

    expect(installation.reporting_state(at: now)).to eq("reporting")
    installation.last_seen_at = now - 15.minutes
    expect(installation.reporting_state(at: now)).to eq("stale")
    installation.last_seen_at = now - 60.minutes
    expect(installation.reporting_state(at: now)).to eq("offline")
  end

  it "treats an installation without a heartbeat as offline" do
    installation = described_class.new

    expect(installation.reporting_state).to eq("offline")
  end
end
