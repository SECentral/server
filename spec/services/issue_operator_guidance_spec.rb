require "rails_helper"

RSpec.describe IssueOperatorGuidance do
  def occurrence(id: 1, host_id: 1, path: "/var/www/html/a 'quoted';$(bad).txt", permissions: ["read"], object_class: "file")
    denial = instance_double(NormalizedDenial, details: { "target_evidence" => { "filesystem_paths" => [path].compact } },
      permissions: permissions, target_class: object_class, target_type: "user_home_t", source_type: "httpd_t")
    host = instance_double(Host, hostname: "host-#{host_id}")
    instance_double(Occurrence, id: id, host_id: host_id, host: host, normalized_denial: denial, occurred_at: Time.utc(2026, 10, 1))
  end

  def issue_with(*items)
    relation = double("occurrences")
    allow(relation).to receive(:includes).with(:host, :normalized_denial).and_return(relation)
    allow(relation).to receive(:order).with(occurred_at: :desc, id: :desc).and_return(relation)
    allow(relation).to receive(:to_a).and_return(items)
    instance_double(Issue, occurrences: relation)
  end

  it "generates literal current/expected/preview checks, never mutating commands or observed local results" do
    item = occurrence
    result = described_class.call(issue_with(item))
    commands = result[:checks].map { |check| Shellwords.split(check[:command]) }
    path = item.normalized_denial.details.dig("target_evidence", "filesystem_paths").first
    expect(commands).to eq([["ls", "-ldZ", "--", path], ["matchpathcon", "--", path], ["restorecon", "-n", "-v", "--", path]])
    expect(result[:checks].last[:interpretation]).to include("may do nothing", "investigate configuration")
    expect(result[:source]).to include(occurrence_id: 1, host_id: 1, path: path)
    expect(result).not_to have_key(:current_label)
    expect(result[:verification_limit]).to include("permissiveness", "event-delivery")
    expect(result[:verification]).not_to match(/query|database|initialize/)
  end

  it "supplies scoped read-only capability checks without an invented service unit, PID or historical policy" do
    item = occurrence(path: nil, permissions: ["net_admin"], object_class: "capability")
    allow(item).to receive(:raw_event).and_return(nil)
    allow(item.normalized_denial).to receive(:executable).and_return("/usr/sbin/a 'quoted';$(bad)")
    result = described_class.call(issue_with(item))
    commands = result[:checks].map { |check| Shellwords.split(check[:command]) }
    expect(commands.first).to eq(["journalctl", "--utc", "--since", "2026-09-30 23:59:00 UTC", "--until", "2026-10-01 00:01:00 UTC", "_EXE=/usr/sbin/a 'quoted';$(bad)"])
    expect(commands[1]).to eq(["ps", "-eZ", "-o", "label,pid,comm"])
    expect(commands.last).to eq(["sesearch", "-A", "-s", "httpd_t", "-t", "user_home_t", "-c", "capability", "-p", "net_admin"])
    expect(result[:capability]).to include(explanation: include("administrator privileges"))
    expect(result[:possible_fix]).to include("No reviewed capability change")
    expect(result[:verification]).to include("workload operation", "enforcement mode")
    allow(item.normalized_denial).to receive(:executable).and_return(nil)
    expect(described_class.call(issue_with(item))[:checks].first[:command]).to start_with("ps ")
  end

  it "ties the investigation to the diagnosis or triage path's actual occurrence and host" do
    latest = occurrence(id: 2, host_id: 2, path: "/var/www/html/z")
    older = occurrence(path: "/var/www/html/a")
    issue = issue_with(latest, older)
    expect(described_class.call(issue, diagnosis: { occurrence_id: 1, path: "/var/www/html/a" })[:source]).to include(host_id: 1, occurrence_id: 1)
    expect(described_class.call(issue, triage_guidance: { path: "/var/www/html/a" })[:source]).to include(host_id: 1, occurrence_id: 1)
    expect(described_class.call(issue, diagnosis: { occurrence_id: 999 })).to be_nil
  end

  it "suppresses path-specific commands for basename, ambiguous or noncanonical paths" do
    [nil, "name.txt", "/var/www/../private/file", "/var/www/html/file\nother"].each do |path|
      result = described_class.call(issue_with(occurrence(path: path)))
      expect(result[:checks]).to be_empty
      expect(result[:source][:path]).to be_nil
      expect(result[:manual_check]).to include("Identify the complete absolute path")
    end
    item = occurrence
    allow(item.normalized_denial).to receive(:details).and_return({ "target_evidence" => { "filesystem_paths" => ["/srv/a", "/srv/b"] } })
    expect(described_class.call(issue_with(item))[:checks]).to be_empty
  end

  it "provides operation-specific network and execution checks without solving conditions or inventing endpoints" do
    condition = { condition_boolean_states: [{ booleans: [{ "name" => "httpd_can_network_connect" }, { "name" => "bad;command" }] }] }
    connect = described_class.call(issue_with(occurrence(path: nil, permissions: ["name_connect"], object_class: "tcp_socket")), diagnosis: condition.merge(occurrence_id: 1))
    expect(connect[:checks].map { |item| item[:command] }).to include("getsebool httpd_can_network_connect")
    expect(connect[:checks].first[:command]).to eq("getsebool httpd_can_network_connect")
    expect(connect[:checks].map { |item| item[:command] }.join).not_to include("bad;command", "setsebool")
    expect(connect[:verification]).to include("backend response")
    bind = described_class.call(issue_with(occurrence(path: nil, permissions: ["name_bind"], object_class: "tcp_socket")))
    expect(bind[:checks].first[:command]).to eq("ss -ltnp")
    expect(bind[:possible_fix]).to include("using an appropriate existing endpoint", "Mapping options require exact policy support")
    execute = described_class.call(issue_with(occurrence(permissions: ["execute"])))
    expect(execute[:verification]).to include("actual child process context")
    expect(execute[:possible_fix]).to include("inspect its current and configured labels", "Confirm execution is intended")
  end

  it "starts a missing-path home-content read with object identity and intent, not restoration" do
    result = described_class.call(issue_with(occurrence(path: nil)))
    expect(result[:possible_fix]).to start_with("Identify the object")
    expect(result[:possible_fix]).to include("serving home-directory content", "Once the path is known", "matchpathcon", "Restore only", "misplaced", "broader host-wide read access")
    expect(result[:verification]).not_to include("query", "database")
    expect(result[:checks]).to be_empty
  end

  it "does not turn an entrypoint labeling mismatch into a web-read fix or execution guarantee" do
    result = described_class.call(issue_with(occurrence(permissions: ["entrypoint"])))
    expect(result[:manual_check]).to include("intended launch", "executable identity", "requested execution context")
    expect(result[:possible_fix]).to include("inspect its current and configured labels", "Confirm execution is intended")
    expect(result[:verification]).to start_with("Retry only the intended launch")
  end

  it "places direct workload-source Boolean checks before attribute alternatives and port inventories" do
    diagnosis = { occurrence_id: 1, condition_boolean_states: [
      { rule: "allow nsswitch_domain unreserved_port_t:tcp_socket name_connect;", booleans: [{ name: "nis_enabled" }] },
      { rule: "allow httpd_t port_type:tcp_socket name_connect;", booleans: [{ name: "httpd_can_network_connect" }] }
    ] }
    result = described_class.call(issue_with(occurrence(path: nil, permissions: ["name_connect"], object_class: "tcp_socket")), diagnosis: diagnosis)
    expect(result[:checks].map { |item| item[:command] }).to eq(["getsebool httpd_can_network_connect", "getsebool nis_enabled", "semanage port -l", "semanage port -l -C", "sesearch -A -s httpd_t -c tcp_socket -p name_connect"])
    expect(result[:possible_fix]).to include("already observed On")
  end

  it "puts TCP/UDP bind ownership and effective/local classifications before matching Boolean paths" do
    %w[tcp_socket udp_socket].each do |object_class|
      diagnosis = { occurrence_id: 1, condition_boolean_states: [{ rule: "allow nsswitch_domain unreserved_port_t:#{object_class} name_bind;", booleans: [{ name: "nis_enabled" }] }] }
      result = described_class.call(issue_with(occurrence(path: nil, permissions: ["name_bind"], object_class: object_class)), diagnosis: diagnosis)
      expect(result[:manual_check]).to include("intended listener", "actual configuration")
      expect(result[:checks].first(3).map { |check| check[:command] }).to eq([object_class == "udp_socket" ? "ss -lunp" : "ss -ltnp", "semanage port -l", "semanage port -l -C"])
      expect(result[:checks].last[:command]).to eq("getsebool nis_enabled")
      expect(result[:checks].last[:interpretation]).to include("current runtime state", "retrying the intended workload")
    end
  end

  it "shares scoped port checks for enforcing and non-enforced AVCs without sharing findings" do
    %w[tcp_socket udp_socket].each do |object_class|
      commands = [false, true].map do |permissive|
        item = occurrence(path: nil, permissions: ["name_bind"], object_class: object_class)
        allow(item.normalized_denial).to receive(:details).and_return({ "permissive" => permissive, "network_evidence" => { "bind_port_fields" => ["9090"] } })
        result = described_class.call(issue_with(item), occurrence: item)
        expect(result[:source]).to include(host_id: item.host_id, occurrence_id: item.id, port: 9090)
        result[:checks].map { |check| check[:command] }
      end
      expect(commands.first).to eq(commands.last)
      expect(Shellwords.split(commands.first.first)).to eq(["ss", object_class == "tcp_socket" ? "-ltnp" : "-lunp", "sport = :9090"])
      expect(commands.first.last).to eq("sesearch -A -s httpd_t -c #{object_class} -p name_bind")
    end
  end
end
