require "rails_helper"

RSpec.describe ConfigurationDrift do
  after do
    HostSnapshotObservation.delete_all
    HostSnapshot.delete_all
    AgentInstallation.delete_all
    Host.delete_all
    Organization.delete_all
  end

  it "reports added, removed, and changed snapshot state" do
    organization = Organization.create!(name: "drift")
    host = organization.hosts.create!(external_id: "drift-host", last_seen_at: Time.current)
    observe(host, details("old_t", "1", false), 1.hour.ago)
    observe(host, details("new_t", "1", true), 30.minutes.ago)
    observe(host, details("new_t", "2", false), Time.current)

    result = described_class.call(host)

    expect(result.map { |transition| transition[:family] }).to include("file_contexts", "modules")
    file_changes = result.select { |transition| transition[:family] == "file_contexts" }
    module_changes = result.select { |transition| transition[:family] == "modules" }
    expect(file_changes.flat_map { |transition| transition[:changed] }).not_to be_empty
    expect(module_changes.flat_map { |transition| transition[:changed] }).not_to be_empty
    expect(file_changes.sum { |transition| transition[:added].size + transition[:added_count].to_i }).not_to eq(0)
    expect(file_changes.flat_map { |transition| transition[:removed] }).not_to be_empty
  end

  private

  def observe(host, details, at)
    snapshot = host.host_snapshots.create!(details: details)
    installation = host.agent_installations.first || host.organization.agent_installations.create!(name: "agent-#{host.external_id}", bound_host: host)
    host.host_snapshot_observations.create!(agent_installation: installation, host_snapshot: snapshot, first_observed_at: at, last_observed_at: at, first_received_at: at, last_received_at: at)
  end

  def details(context, version, include_new)
    { "selinux" => { "kernel_policy_version" => version, "policy" => {
      "file_contexts" => [{ "pattern" => "/srv/app", "file_type" => "all files", "context" => "system_u:object_r:#{context}:s0", "provenance" => "custom" }].then { |values| include_new ? values << { "pattern" => "/new", "file_type" => "all files", "context" => "system_u:object_r:new_t:s0", "provenance" => "custom" } : values },
      "modules" => [{ "name" => "local_web", "priority" => 400, "version" => version, "provenance" => "custom" }]
    } } }
  end
end
