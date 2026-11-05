require "rails_helper"

RSpec.describe ConfigurationDrift do
  around do |example|
    ActiveRecord::Base.transaction do
      example.run
      raise ActiveRecord::Rollback
    end
  end

  let(:organization) { Organization.create!(name: "drift") }
  let(:host) { organization.hosts.create!(external_id: "drift-host") }
  let(:installation) { organization.agent_installations.create!(name: "agent", bound_host: host) }
  let(:at) { Time.utc(2026, 1, 1, 10) }

  it "reports exact forward changes and coalesced sampled bounds" do
    first = observe(details("1", %w[old same]), at, last_observed_at: at + 5.minutes, last_received_at: at + 6.minutes)
    second = observe(details("2", %w[new same]), at + 10.minutes)
    result = described_class.call(host)
    files = result.find { |item| item[:family] == "file_contexts" }
    modules = result.find { |item| item[:family] == "modules" }
    expect(files).to include(direction: "ordered", from: (at + 5.minutes).iso8601(6), to: (at + 10.minutes).iso8601(6))
    expect(files[:epochs].pluck(:observation_id)).to eq([first.id, second.id])
    expect(files[:added].pluck("pattern")).to eq(["new"])
    expect(files[:removed].pluck("pattern")).to eq(["old"])
    expect(files[:changed].sole).to include(before: hash_including("context" => "1"), after: hash_including("context" => "2"))
    expect(modules[:changed].sole).to include(before: hash_including("version" => "1"), after: hash_including("version" => "2"))
  end

  it "uses ascending id for equal receipt times" do
    first = observe(details("1"), at, first_received_at: at + 1.hour, last_received_at: at + 1.hour)
    second = observe(details("2"), at + 1.minute, first_received_at: at + 1.hour, last_received_at: at + 1.hour)
    transition = described_class.call(host).find { |item| item[:family] == "modules" }
    expect(transition[:epochs].pluck(:observation_id)).to eq([first.id, second.id])
    expect(transition[:changed].sole[:after]["version"]).to eq("2")
  end

  {
    "tied observations" => [{}, { first_observed_at: 0 }, "overlapping_observed_bounds"],
    "overlapping observations" => [{ last_observed_at: 20 }, { first_observed_at: 10 }, "overlapping_observed_bounds"],
    "backwards observations" => [{ first_observed_at: 20, last_observed_at: 20 }, { first_observed_at: 10 }, "overlapping_observed_bounds"],
    "inverted observed bounds" => [{ first_observed_at: 2, last_observed_at: 1 }, {}, "invalid_observed_bounds"],
    "inverted receipt bounds" => [{ last_received_at: -1 }, {}, "invalid_receipt_bounds"]
  }.each do |label, (first_offsets, second_offsets, reason)|
    it "marks #{label} unknown" do
      first = observe(details("1"), at, **offsets(first_offsets))
      second = observe(details("2"), at + 10.seconds, **offsets(second_offsets))
      assert_unknown(first, second, reason)
    end
  end

  [nil, "", "  ", 123, "different"].each do |boot|
    it "marks boot ID #{boot.inspect} unknown" do
      first = observe(details("1"), at)
      second_details = details("2").merge("boot_id" => boot)
      second = observe(second_details, at + 1.minute)
      assert_unknown(first, second, boot == "different" ? "different_boot_ids" : "unknown_boot_id")
    end
  end

  it "treats an absent boot ID and an otherwise baseline-like difference as unknown" do
    empty = details("1").tap { |d| d["selinux"]["policy"]["file_contexts"] = [] }
    first = observe(empty, at)
    second = observe(details("1").except("boot_id"), at + 1.minute)
    entry = described_class.call(host).find { |item| item[:family] == "file_contexts" }
    expect(entry).to include(direction: "unknown", values_differ: true, reasons: include("unknown_boot_id"))
    expect(entry[:epochs].pluck(:observation_id)).to eq([first.id, second.id])
    expect(entry.keys).not_to include(:baseline, :added, :removed, :changed, :added_count, :removed_count, :changed_count, :from, :to)
  end

  it "preserves baseline and provenance-only classification for ordered pairs" do
    empty = details("1").tap { |d| d["selinux"]["policy"]["file_contexts"] = [] }
    observe(empty, at)
    observe(details("1"), at + 1.minute)
    provenance = details("1")
    provenance["selinux"]["policy"]["file_contexts"][0]["provenance"] = "distribution"
    observe(provenance, at + 2.minutes)
    transitions = described_class.call(host).select { |item| item[:family] == "file_contexts" }
    expect(transitions.map { |item| item.slice(:baseline, :added_count, :changed_count, :added, :changed) }).to eq([
      { baseline: true, added_count: 1, changed_count: 0, added: [], changed: [] },
      { baseline: true, added_count: 0, changed_count: 0, added: [], changed: [] }
    ])
  end

  def offsets(values)
    values.transform_values { |seconds| at + seconds.seconds }
  end

  def assert_unknown(first, second, reason)
    entry = described_class.call(host).find { |item| item[:family] == "modules" }
    expect(entry).to include(direction: "unknown", values_differ: true, reasons: include(reason))
    expect(entry[:epochs].pluck(:observation_id)).to eq([first.id, second.id])
    expect(entry.keys).not_to include(:from, :to, :baseline, :added, :removed, :changed, :added_count, :removed_count, :changed_count)
  end

  def observe(value, time, **attributes)
    snapshot = host.host_snapshots.create!(details: value)
    host.host_snapshot_observations.create!({ agent_installation: installation, host_snapshot: snapshot,
      first_observed_at: time, last_observed_at: time, first_received_at: time, last_received_at: time }.merge(attributes))
  end

  def details(version, paths = ["same"])
    { "boot_id" => "boot-1", "selinux" => { "policy" => {
      "file_contexts" => paths.map { |path| { "pattern" => path, "file_type" => "all", "context" => path == "same" ? version : "context", "provenance" => "custom" } },
      "modules" => [{ "name" => "local_web", "priority" => 400, "version" => version, "provenance" => "custom" }]
    } } }
  end
end
