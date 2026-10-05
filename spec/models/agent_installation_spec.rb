require "rails_helper"

RSpec.describe AgentInstallation, type: :model do
  let(:organization) { Organization.create!(name: "agent-state") }

  after do
    AgentInstallation.delete_all
    Host.delete_all
    Organization.delete_all
  end

  it "uses reporting, stale, and offline boundaries based on heartbeat age" do
    installation = organization.agent_installations.create!(name: "agent", last_seen_at: 1.second.ago)
    now = Time.current

    expect(installation.reporting_state(at: now)).to eq("reporting")
    installation.update!(last_seen_at: now - 15.minutes)
    expect(installation.reporting_state(at: now)).to eq("stale")
    installation.update!(last_seen_at: now - 60.minutes)
    expect(installation.reporting_state(at: now)).to eq("offline")
  end

  it "treats an installation without a heartbeat as offline" do
    installation = organization.agent_installations.create!(name: "agent")

    expect(installation.reporting_state).to eq("offline")
  end
end
