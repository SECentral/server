require "rails_helper"

RSpec.describe IssueTriageSignals do
  after do
    Occurrence.delete_all
    NormalizedDenial.delete_all
    IssueDispositionChange.delete_all
    Issue.delete_all
    RawEvent.delete_all
    HostSnapshotObservation.delete_all
    HostSnapshot.delete_all
    AgentInstallation.delete_all
    Host.delete_all
    Organization.delete_all
  end

  it "emits deterministic outlier, concentration, and frequency signals" do
    evaluated_at = Time.current.change(usec: 0)
    organization = Organization.create!(name: "signals")
    issue = create_issue(organization, evaluated_at - 20.days)
    host = create_host(organization, "one", "42")
    3.times { |index| create_occurrence(issue, host, evaluated_at - (index + 1).hours, index + 1) }
    create_occurrence(issue, host, evaluated_at - 10.days, 4)
    9.times { |index| create_host(organization, "other-#{index}", "42") }

    result = described_class.call(issue, evaluated_at: evaluated_at)
    codes = result[:signals].map { |signal| signal[:code] }

    expect(codes).to include("fleet_outlier", "host_concentration", "frequency_increase")
    concentration = result[:signals].find { |signal| signal[:code] == "host_concentration" }
    expect(concentration[:evidence]).to include(recent_hosts_with_occurrences: 1, hostname: "one")
    expect(result[:signals]).to all(include(certainty: "derived"))
    expect(result[:windows]).to eq(recent_days: 7, baseline_days: 30)
  end

  it "emits novelty signals without inventing a diagnosis" do
    evaluated_at = Time.current.change(usec: 0)
    organization = Organization.create!(name: "novelty")
    issue = create_issue(organization, evaluated_at - 1.day)
    host = create_host(organization, "new-host", "42")
    create_occurrence(issue, host, evaluated_at - 1.day, 1)

    result = described_class.call(issue, evaluated_at: evaluated_at)

    codes = result[:signals].map { |signal| signal[:code] }
    expect(codes).to include("new_issue")
    expect(codes).not_to include("new_host_issue")
    expect(result[:signals].map(&:keys).flatten).not_to include(:risk, :probability, :diagnosis)
  end

  it "reports policy prevalence with both cohort denominators" do
    evaluated_at = Time.current.change(usec: 0)
    organization = Organization.create!(name: "policy-correlation")
    issue = create_issue(organization, evaluated_at - 10.days)
    3.times do |index|
      host = create_host(organization, "affected-#{index}", "42")
      create_occurrence(issue, host, evaluated_at - 1.day, index + 1)
    end
    7.times { |index| create_host(organization, "unaffected-#{index}", "99") }

    signal = described_class.call(issue, evaluated_at: evaluated_at)[:signals].find { |item| item[:code] == "policy_version_correlation" }

    expect(signal[:evidence][:correlations]).to include(
      policy_version: "42",
      with_occurrence: { hosts: 3, total: 3 },
      without_occurrence: { hosts: 0, total: 7 }
    )
  end

  it "suppresses comparisons when their baseline or cohorts are insufficient" do
    evaluated_at = Time.current.change(usec: 0)
    organization = Organization.create!(name: "insufficient-data")
    issue = create_issue(organization, evaluated_at - 1.day)
    host = create_host(organization, "only-host", "42")
    create_occurrence(issue, host, evaluated_at - 1.hour, 1)

    codes = described_class.call(issue, evaluated_at: evaluated_at)[:signals].map { |signal| signal[:code] }

    expect(codes).not_to include("frequency_increase", "policy_version_correlation")
  end

  it "does not call an issue an outlier when no active host has an occurrence" do
    evaluated_at = Time.current.change(usec: 0)
    organization = Organization.create!(name: "inactive")
    issue = create_issue(organization, evaluated_at - 2.days)
    host = create_host(organization, "old-host", "42")
    host.update!(last_seen_at: 10.days.ago)
    create_occurrence(issue, host, evaluated_at - 1.day, 1)
    create_host(organization, "active-host", "42")

    expect(described_class.call(issue, evaluated_at: evaluated_at)[:signals].map { |signal| signal[:code] }).not_to include("fleet_outlier")
  end

  private

  def create_issue(organization, first_seen_at)
    Issue.create!(organization: organization, fingerprint_version: 3, fingerprint_digest: SecureRandom.hex(8), source_type: "httpd_t", target_type: "default_t", target_class: "file", permissions: ["read"], first_seen_at: first_seen_at, last_seen_at: first_seen_at)
  end

  def create_host(organization, external_id, policy)
    host = organization.hosts.create!(external_id: external_id, hostname: external_id, last_seen_at: Time.current)
    snapshot = host.host_snapshots.create!(details: { "selinux" => { "kernel_policy_version" => policy } })
    installation = organization.agent_installations.create!(name: "agent-#{external_id}", bound_host: host)
    host.host_snapshot_observations.create!(agent_installation: installation, host_snapshot: snapshot, first_observed_at: Time.current, last_observed_at: Time.current, first_received_at: Time.current, last_received_at: Time.current)
    host
  end

  def create_occurrence(issue, host, occurred_at, sequence)
    snapshot = host.current_snapshot
    installation = issue.organization.agent_installations.create!(name: "agent-#{host.external_id}-#{sequence}")
    raw_event = RawEvent.create!(organization: issue.organization, agent_installation: installation, host: host, host_snapshot: snapshot, audit_timestamp: occurred_at, audit_sequence: sequence, boot_id: "boot-#{host.external_id}", completion_reason: "eoe", evidence_digest: SecureRandom.hex(8), host_observed_at: occurred_at, agent_received_at: occurred_at, server_received_at: occurred_at, schema_version: 2)
    denial = NormalizedDenial.create!(raw_event: raw_event, ordinal: 0, normalization_version: 1, status: "ok", source_type: "httpd_t", target_type: "default_t", target_class: "file", permissions: ["read"], details: { "target_evidence" => { "filesystem_paths" => [], "object_names" => [] } })
    Occurrence.create!(organization: issue.organization, host: host, host_snapshot: snapshot, raw_event: raw_event, normalized_denial: denial, issue: issue, occurred_at: occurred_at)
  end
end
