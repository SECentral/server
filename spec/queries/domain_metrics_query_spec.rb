require "rails_helper"

RSpec.describe DomainMetricsQuery do
  include ActiveSupport::Testing::TimeHelpers

  let(:organization) { Organization.create!(name: "metrics") }
  let(:now) { Time.utc(2026, 11, 3, 12) }

  around do |example|
    # Other specs use nontransactional fixtures; start aggregates from a clean baseline.
    [Occurrence.unscoped, NormalizedDenial, IssueDispositionChange, IssueSignature, Issue,
      RawAuditRecord, RawEvent, HostSnapshotObservation, HostSnapshot, HostReportingDay,
      AgentInstallation, Host, Organization].each(&:delete_all)
    ActiveRecord::Base.transaction do
      travel_to(now) { example.run }
      raise ActiveRecord::Rollback
    end
  end

  it "returns empty aggregates without inventing records" do
    result = described_class.new.call
    expect(result.to_h).to eq(issues: {}, regressed_issues: 0, occurrences: 0,
      ungrouped_occurrences: 0, hosts: 0, hosts_by_selinux_enforcement: {},
      hosts_with_open_issues: 0, agent_installations: {})
  end

  it "preserves issue correlation, including mixed, without counting signatures" do
    Issue::STATUSES.product(Issue::DISPOSITIONS + ["mixed"]).each do |status, disposition|
      issue(status: status, disposition: disposition)
    end
    item = Issue.first
    2.times do |index|
      item.signatures.create!(fingerprint_version: 3, fingerprint_digest: "signature-#{index}",
        permissions: ["read"], first_seen_at: now, last_seen_at: now)
    end
    other = Organization.create!(name: "other")
    issue(organization: other, status: "open", disposition: "suspicious_behavior")

    counts = described_class.new.call.issues
    expect(counts.size).to eq(27)
    expect(counts.values.sum).to eq(28)
    expect(counts.fetch(["open", "suspicious_behavior"])).to eq(2)
    expect(counts.fetch(["resolved", "suspicious_behavior"])).to eq(1)
  end

  it "uses current regression semantics, with regressions still included in open counts" do
    issue(regressions_count: 3)
    issue(reopened_at: now)
    issue(reopened_at: now, resolved_at: now - 1)
    issue(reopened_at: now, resolved_at: now)
    issue(reopened_at: now - 1, resolved_at: now)
    issue(status: "resolved", reopened_at: now)
    issue(status: "ignored", reopened_at: now)

    result = described_class.new.call
    expect(result.regressed_issues).to eq(2)
    expect(result.issues.fetch(["open", "unclassified"])).to eq(5)
    expect(result.regressed_issues).to eq(Issue.all.count { |item| item.display_status == "regressed" })
  end

  it "counts live occurrences and distinct affected hosts, not stale counters or retired interpretations" do
    first, second, retired = Array.new(3) { host }
    opened = issue
    resolved = issue(status: "resolved")
    ignored = issue(status: "ignored")
    2.times { occurrence(first, opened) }
    occurrence(second, opened)
    occurrence(retired, opened, superseded_at: now)
    occurrence(first, resolved)
    occurrence(retired, ignored)
    occurrence(second, nil)
    opened.update_column(:occurrences_count, 999)

    result = described_class.new.call
    expect(result.occurrences).to eq(6)
    expect(result.ungrouped_occurrences).to eq(1)
    expect(result.hosts_with_open_issues).to eq(2)
  end

  it "counts installations rather than hosts with the exact recent-contact boundaries" do
    owner = host
    [nil, now - 3600, now - 3599, now - 900, now - 899, now + 60].each do |seen|
      organization.agent_installations.create!(name: SecureRandom.uuid, bound_host: owner, last_seen_at: seen)
    end
    organization.agent_installations.create!(name: "unbound", last_seen_at: now)
    host

    result = described_class.new.call
    expect(result.agent_installations).to eq("offline" => 2, "stale" => 2, "reporting" => 3)
    expect(result.hosts).to eq(2)
    expected = AgentInstallation.all.group_by { |item| item.reporting_state(at: now) }.transform_values(&:size)
    expect(result.agent_installations).to eq(expected)
  end

  it "classifies fresh modes and missing, stale, or unrecognized evidence exactly once per host" do
    %w[enforcing permissive disabled unknown unexpected].each { |mode| observe(host, mode: mode) }
    observe(host, mode: nil)
    observe(host, received_at: now - 900)
    observe(host, received_at: now - 900 - 0.000001)
    host

    result = described_class.new.call
    expect(result.hosts_by_selinux_enforcement).to eq("enforcing" => 2, "permissive" => 1, "disabled" => 1, "unknown" => 5)
    expect(result.hosts_by_selinux_enforcement.values.sum).to eq(result.hosts)
    expect_enforcement_parity
  end

  it "selects by receipt then ID, not snapshot creation or observation time, without known-mode fallback" do
    owner = host
    observe(owner, mode: "enforcing", observed_at: now + 20)
    observe(owner, mode: "permissive", received_at: now - 1, observed_at: now + 40)
    observe(owner, mode: "unknown", observed_at: now - 20)
    HostSnapshot.create!(host: owner, details: { "selinux" => { "enforcement" => "disabled" } })

    expect(described_class.new.call.hosts_by_selinux_enforcement).to eq("unknown" => 1)
    expect_enforcement_parity
  end

  [
    ["enforcement_change", [], "selinux_administrative", 0, "boot", "unknown"],
    ["enforcement_change", [], "selinux_administrative", 1, "boot", "unknown"],
    ["enforcement_change", [], "selinux_administrative", -1, "boot", "enforcing"],
    ["enforcement_change", [], "selinux_administrative", 1, "other-boot", "enforcing"],
    [nil, ["enforcement"], "avc", 1, "boot", "unknown"],
    ["policy_load", ["enforcement"], "selinux_administrative", 1, "boot", "unknown"],
    [nil, ["enforcement"], "selinux_administrative", 1, "boot", "enforcing"],
    ["policy_load", ["policy_identity"], "selinux_administrative", 1, "boot", "enforcing"],
    ["boolean_change", ["booleans"], "selinux_administrative", 1, "boot", "enforcing"],
    ["port_change", ["ports"], "selinux_administrative", 1, "boot", "enforcing"],
    ["file_context_change", ["file_context_mappings"], "selinux_administrative", 1, "boot", "enforcing"]
  ].each do |transition, mask, category, offset, boot, expected|
    it "matches checkpoint trust for #{[transition, mask, category, offset, boot].inspect}" do
      owner = host
      observe(owner)
      event(owner, transition_type: transition, checkpoint_invalidated_fields: mask,
        category: category, audit_timestamp: now + offset, boot_id: boot)
      expect(described_class.new.call.hosts_by_selinux_enforcement).to eq(expected => 1)
      expect_enforcement_parity
    end
  end

  it "does not add a host boot comparison and allows a later checkpoint to restore trust" do
    owner = host
    owner.update!(boot_id: "different-host-column")
    observe(owner)
    expect(described_class.new.call.hosts_by_selinux_enforcement).to eq("enforcing" => 1)
    event(owner, transition_type: "enforcement_change", audit_timestamp: now + 1)
    expect(described_class.new.call.hosts_by_selinux_enforcement).to eq("unknown" => 1)
    observe(owner, mode: "permissive", observed_at: now + 2)
    expect(described_class.new.call.hosts_by_selinux_enforcement).to eq("permissive" => 1)
    observe(owner, mode: "disabled", boot: "new-boot")
    expect(described_class.new.call.hosts_by_selinux_enforcement).to eq("disabled" => 1)
    expect_enforcement_parity
  end

  it "keeps a fixed aggregate query count without instantiating the fleet" do
    counts = [1, 5].map do |size|
      size.times { observe(host) }
      queries = []
      instantiated = []
      sql = ->(event) { queries << event.payload[:sql] unless event.payload[:name] == "SCHEMA" }
      models = ->(event) { instantiated << event.payload }
      ActiveSupport::Notifications.subscribed(sql, "sql.active_record") do
        ActiveSupport::Notifications.subscribed(models, "instantiation.active_record") do
          ActiveRecord::Base.uncached { described_class.new.call }
        end
      end
      expect(instantiated).to be_empty
      queries.size
    end
    expect(counts).to eq([7, 7])
  end

  it "distinguishes heartbeat/event contact from accepted configuration refresh" do
    travel_to(now - 3601)
    payload = { "schema_version" => 2, "agent" => { "version" => "test" },
      "host_observed_at" => Time.current.iso8601,
      "host" => { "id" => "contact-host", "boot_id" => "boot", "selinux" => { "enforcement" => "enforcing" } } }
    Heartbeat.call(organization: organization, payload: payload)
    expect(described_class.new.call.agent_installations).to eq("reporting" => 1)
    travel_to(now)
    expect(described_class.new.call.agent_installations).to eq("offline" => 1)

    timestamp = (now - 1).iso8601
    IngestEvents.new(organization: organization, payload: {
      "schema_version" => 4, "agent" => { "version" => "test" }, "host_id" => "contact-host", "boot_id" => "boot",
      "events" => [{ "category" => "selinux_administrative", "audit_event" => { "timestamp" => timestamp, "sequence" => 1 },
        "agent_received_at" => timestamp, "completion_reason" => "eoe",
        "records" => [{ "position" => 0, "type" => 1404, "type_name" => "MAC_STATUS", "timestamp" => timestamp,
          "sequence" => 1, "payload" => Base64.strict_encode64("enforcing=0 old_enforcing=1 enabled=1 old-enabled=1 lsm=selinux res=0") }] }]
    }).call
    result = described_class.new.call
    expect(result.agent_installations).to eq("reporting" => 1)
    expect(result.hosts_by_selinux_enforcement).to eq("unknown" => 1)

    # Earlier observation is rejected even though the agent made fresh contact.
    payload["host_observed_at"] = (now - 3602).iso8601
    Heartbeat.call(organization: organization, payload: payload)
    expect(HostSnapshotObservation.sole.last_received_at).to eq(now - 3601)
    expect(described_class.new.call.hosts_by_selinux_enforcement).to eq("unknown" => 1)

    payload["host_observed_at"] = now.iso8601
    payload["host"]["boot_id"] = "new-boot"
    Heartbeat.call(organization: organization, payload: payload)
    expect(described_class.new.call.hosts_by_selinux_enforcement).to eq("enforcing" => 1)
    expect_enforcement_parity
  end

  def expect_enforcement_parity
    expected = Host.all.map do |owner|
      owner.current_configuration? ? (owner.enforcement_for || "unknown") : "unknown"
    end.tally
    expect(described_class.new.call.hosts_by_selinux_enforcement).to eq(expected)
  end

  def host
    organization.hosts.create!(external_id: SecureRandom.uuid)
  end

  def issue(**attributes)
    Issue.create!({ organization: organization, fingerprint_version: 3, fingerprint_digest: SecureRandom.hex,
      source_type: SecureRandom.hex, target_type: "target_t", target_class: "file",
      first_seen_at: now, last_seen_at: now }.merge(attributes))
  end

  def installation(owner)
    owner.agent_installations.first || organization.agent_installations.create!(name: owner.external_id, bound_host: owner)
  end

  def observe(owner, mode: "enforcing", received_at: now, observed_at: now, boot: "boot")
    snapshot = owner.host_snapshots.create!(details: { "boot_id" => boot, "selinux" => { "enforcement" => mode } })
    owner.host_snapshot_observations.create!(host_snapshot: snapshot, agent_installation: installation(owner),
      first_observed_at: observed_at, last_observed_at: observed_at,
      first_received_at: received_at, last_received_at: received_at)
  end

  def event(owner, **attributes)
    RawEvent.create!({ organization: organization, host: owner, agent_installation: installation(owner),
      audit_timestamp: now, audit_sequence: RawEvent.count + 1, boot_id: "boot", completion_reason: "eoe",
      evidence_digest: SecureRandom.hex, agent_received_at: now, server_received_at: now, schema_version: 4 }.merge(attributes))
  end

  def occurrence(owner, item, **attributes)
    raw = event(owner)
    denial = NormalizedDenial.create!(raw_event: raw, ordinal: 0, normalization_version: 1, status: "ok")
    Occurrence.create!({ organization: organization, host: owner, raw_event: raw,
      normalized_denial: denial, issue: item, occurred_at: now }.merge(attributes))
  end
end
