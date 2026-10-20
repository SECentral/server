require "rails_helper"

RSpec.describe IssueActivityGroups do
  def event(id, permissions, at: Time.utc(2026, 10, 20), pid: "42", inode: "100", device: "vda1", host: 1, boot: "boot", serial: id,
    path: "/var/www/html/test.html", mode: "permissive", context: "system_u:object_r:user_home_t:s0", success: "yes", command: "httpd")
    records = permissions.map do |permission|
      "type=AVC avc: denied { #{permission} } for pid=#{pid} comm=\"#{command}\" dev=#{device} ino=#{inode} path=\"#{path}\" scontext=system_u:system_r:httpd_t:s0 tcontext=#{context} tclass=file permissive=#{mode == 'permissive' ? 1 : 0}"
    end
    raw = Struct.new(:boot_id, :audit_sequence, :raw_audit_records).new(boot, serial, records)
    details = { "enforcement_mode" => mode, "target_evidence" => { "filesystem_paths" => [path] }, "syscall_evidence" => [{ "success" => success }] }
    denial = Struct.new(:permissions, :target_class, :details, :command, :executable).new(permissions, "file", details, command, "/usr/sbin/httpd")
    Struct.new(:id, :host_id, :raw_event_id, :raw_event, :normalized_denial, :occurred_at).new(id, host, id, raw, denial, at)
  end

  it "groups the permissive open/read and map events without merging the enforcing occurrence" do
    first = event(1, %w[open read])
    second = event(2, ["map"], at: first.occurred_at + 0.001)
    enforcing = event(3, ["read"], host: 2, mode: "enforcing")
    result = described_class.call([enforcing, second, first])
    expect(result.map { |group| group[:occurrence_ids] }).to eq([[3], [1, 2]])
    expect(result.last).to include(correlated: true, basis: include("not proof", "100ms"))
    expect(first.normalized_denial.permissions).to eq(%w[open read])
  end

  {
    "another host" => { host: 2 }, "another boot" => { boot: "other" }, "another PID" => { pid: "43" },
    "another inode" => { inode: "101" }, "another device" => { device: "vdb1" },
    "a different context" => { context: "system_u:object_r:user_home_t:s0:c1" },
    "a different path" => { path: "/var/www/html/other.html" }, "a different process command" => { command: "other" },
    "a failed syscall" => { success: "no" }, "enforcing mode" => { mode: "enforcing" },
    "nonconsecutive audit serials" => { serial: 3 }, "missing inode identity" => { inode: "" }
  }.each do |reason, changes|
    it "does not correlate #{reason}" do
      expect(described_class.call([event(1, %w[open read]), event(2, ["map"], **changes)]).map { |group| group[:occurrence_ids] }).to eq([[1], [2]])
    end
  end

  it "does not group separated accesses, reverse order or sensitive operations" do
    first = event(1, %w[open read])
    [0.101, -0.001].each do |offset|
      expect(described_class.call([first, event(2, ["map"], at: first.occurred_at + offset)]).size).to eq(2)
    end
    [%w[open read write], %w[open read execute], ["read"]].each do |permissions|
      expect(described_class.call([event(1, permissions), event(2, ["map"])]).size).to eq(2)
    end
  end

  it "keeps repeated accesses as distinct two-event groups and does not cross page boundaries" do
    items = [event(1, %w[open read]), event(2, ["map"]), event(3, %w[open read]), event(4, ["map"])]
    expect(described_class.call(items).map { |group| group[:occurrence_ids] }).to eq([[1, 2], [3, 4]])
    expect(described_class.call([items[1]]).sole[:correlated]).to eq(false)
  end

  it "rejects conflicting identity in a multi-AVC event" do
    first = event(1, %w[open read])
    first.raw_event.raw_audit_records[1] = first.raw_event.raw_audit_records[1].sub("ino=100", "ino=200")
    expect(described_class.call([first, event(2, ["map"])]).size).to eq(2)
  end
end
