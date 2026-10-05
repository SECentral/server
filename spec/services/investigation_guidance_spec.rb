require "rails_helper"

RSpec.describe InvestigationGuidance do
  it "does not invent a path from an object name" do
    denial = double(details: { "target_evidence" => { "filesystem_paths" => [], "object_names" => [ "lock" ] } }, target_paths: [], executable: nil)
    occurrence = double(normalized_denial: denial, occurred_at: Time.utc(2026, 9, 1, 14, 20))
    relation = double
    issue = double(permissions: [ "read" ], target_class: "file", occurrences: relation)
    allow(relation).to receive(:includes).with(:normalized_denial, :raw_event).and_return([ occurrence ])

    result = described_class.call(issue: issue, intelligence: { fleet: { current_configuration_hosts: 1, hosts_with_occurrence: 1, hosts_without_occurrence: 0 } })

    expect(result[:missing_evidence]).to include("complete absolute target path from retained audit evidence; expected-context lookup was not run")
    expect(result[:checks].map { |check| check[:kind] }).not_to include(:current_file_label, :expected_file_label)
  end

  it "does not suggest filesystem checks for capability denials" do
    denial = double(details: { "target_evidence" => { "filesystem_paths" => [], "object_names" => [] } }, target_paths: [], permissions: [ "sys_admin" ], executable: nil)
    occurrence = double(normalized_denial: denial, occurred_at: Time.utc(2026, 9, 1, 14, 20))
    relation = double
    issue = double(permissions: [ "sys_admin" ], target_class: "capability", occurrences: relation)
    allow(relation).to receive(:includes).with(:normalized_denial, :raw_event).and_return([ occurrence ])

    result = described_class.call(issue: issue, occurrence: occurrence)

    expect(result[:observations].map { |observation| observation[:observation] }.join).to include("sys_admin", "capability")
    expect(result[:checks].map { |check| check[:kind] }).not_to include(:current_file_label, :expected_file_label)
  end

  it "creates host-specific filesystem checks for a full path" do
    denial = double(details: { "target_evidence" => { "filesystem_paths" => [ "/srv/my app/file" ], "object_names" => [] } }, target_paths: [], permissions: [ "read" ], executable: nil)
    occurrence = double(normalized_denial: denial, occurred_at: Time.utc(2026, 9, 1, 14, 20))
    issue = double(permissions: [ "read" ], target_class: "file")

    result = described_class.call(issue: issue, occurrence: occurrence)
    commands = result[:checks].filter_map { |check| InvestigationCommandRenderer.call(check) }

    expect(commands).to include("ls -lZ /srv/my\\ app/file", "matchpathcon /srv/my\\ app/file")
    expect(result[:checks].map { |check| check[:kind] }).to include(:audit_history)
  end

  it "provides current filesystem checks for an issue with a full path" do
    denial = double(details: { "target_evidence" => { "filesystem_paths" => ["/srv/www/index.html"], "object_names" => [] } }, target_paths: [], permissions: ["read"], executable: nil)
    occurrence = double(normalized_denial: denial, occurred_at: Time.utc(2026, 9, 1, 14, 20))
    relation = double
    issue = double(permissions: ["read"], target_class: "file", occurrences: relation)
    allow(relation).to receive(:includes).with(:normalized_denial, :raw_event).and_return([occurrence])

    result = described_class.call(issue: issue, intelligence: { fleet: { current_configuration_hosts: 1, hosts_with_occurrence: 1, hosts_without_occurrence: 0 } })

    expect(result[:checks].map { |check| check[:kind] }).to include(:current_file_label, :expected_file_label, :parent_file_label)
  end

  it "does not suggest filesystem checks for socket denials" do
    denial = double(details: { "target_evidence" => { "filesystem_paths" => [ "/run/service.sock" ], "object_names" => [] } }, target_paths: [], permissions: [ "connectto" ], executable: nil)
    occurrence = double(normalized_denial: denial, occurred_at: Time.utc(2026, 9, 1, 14, 20))
    issue = double(permissions: [ "connectto" ], target_class: "unix_stream_socket")

    result = described_class.call(issue: issue, occurrence: occurrence)

    expect(result[:observations].map { |observation| observation[:observation] }.join).to include("unix_stream_socket")
    expect(result[:checks].map { |check| check[:kind] }).to include(:socket_context)
    expect(result[:checks].map { |check| check[:kind] }).not_to include(:current_file_label, :expected_file_label)
  end

  it "reports only captured network evidence" do
    denial = double(details: { "target_evidence" => { "filesystem_paths" => [], "object_names" => [] }, "network_evidence" => { "dest_fields" => ["10.0.0.8"], "dport_fields" => ["443"], "lport_fields" => [], "proto_fields" => ["tcp"], "operations" => ["name_connect"] } }, target_paths: [], permissions: [ "name_connect" ], executable: nil)
    occurrence = double(normalized_denial: denial, occurred_at: Time.utc(2026, 9, 1, 14, 20))
    issue = double(permissions: [ "name_connect" ], target_class: "tcp_socket")

    result = described_class.call(issue: issue, occurrence: occurrence)
    text = result[:observations].map { |observation| observation[:observation] }.join(" ")

    expect(text).to include("dest field 10.0.0.8", "dport field 443", "protocol field tcp", "network operation name_connect")
    expect(text).not_to include("service", "example.com")
  end

  it "reports process evidence without claiming a transition" do
    denial = double(details: { "target_evidence" => { "filesystem_paths" => [], "object_names" => [] }, "process_evidence" => { "pids" => ["1842"], "commands" => ["worker"], "executables" => ["/usr/local/bin/worker"], "source_contexts" => ["u:r:worker_t:s0"] } }, target_paths: [], permissions: [ "read" ], executable: "/usr/local/bin/worker")
    occurrence = double(normalized_denial: denial, occurred_at: Time.utc(2026, 9, 1, 14, 20))
    issue = double(permissions: [ "read" ], target_class: "file")

    result = described_class.call(issue: issue, occurrence: occurrence)
    text = result[:observations].map { |observation| observation[:observation] }.join(" ")

    expect(text).to include("process ID 1842", "command worker", "executable /usr/local/bin/worker", "source context u:r:worker_t:s0")
    expect(text).not_to include("transition", "caused")
  end

  it "reports executable evidence without claiming a process transition" do
    denial = double(details: { "target_evidence" => { "filesystem_paths" => [], "object_names" => [] } }, target_paths: [], permissions: [ "read" ], executable: "/usr/sbin/httpd")
    occurrence = double(normalized_denial: denial, occurred_at: Time.utc(2026, 9, 1, 14, 20))
    issue = double(permissions: [ "read" ], target_class: "file")

    result = described_class.call(issue: issue, occurrence: occurrence)

    expect(result[:observations].map { |observation| observation[:observation] }.join).to include("/usr/sbin/httpd")
    expect(result[:checks].map { |check| check[:kind] }).to include(:executable_context)
  end

  it "names the supporting record in evidence observations" do
    denial = double(details: {
      "target_evidence" => { "filesystem_paths" => [], "object_names" => [] },
      "process_evidence" => { "pids" => [], "commands" => [], "executables" => ["/usr/sbin/httpd"], "source_contexts" => [] },
      "evidence_provenance" => [{ "kind" => "executable", "value" => "/usr/sbin/httpd", "source_record_type" => "SYSCALL" }]
    }, target_paths: [], permissions: ["read"], executable: "/usr/sbin/httpd")
    occurrence = double(normalized_denial: denial, occurred_at: Time.utc(2026, 9, 1, 14, 20))
    issue = double(permissions: ["read"], target_class: "file")

    result = described_class.call(issue: issue, occurrence: occurrence)

    expect(result[:observations].find { |observation| observation[:observation].include?("/usr/sbin/httpd") }[:basis]).to eq("syscall_record")
  end

  it "renders event-associated file labels separately from AVC evidence" do
    denial = double(details: {
      "target_evidence" => { "filesystem_paths" => ["/srv/www/index.html"], "object_names" => [] },
      "event_file_contexts" => [{ "path" => "/srv/www/index.html", "context" => "system_u:object_r:httpd_sys_content_t:s0", "status" => "observed" }]
    }, target_paths: [], permissions: ["read"], executable: nil)
    occurrence = double(normalized_denial: denial, occurred_at: Time.utc(2026, 9, 1, 14, 20))
    issue = double(permissions: ["read"], target_class: "file")

    result = described_class.call(issue: issue, occurrence: occurrence)
    text = result[:observations].map { |item| item[:observation] }.join(" ")

    expect(text).to include("event-associated filesystem label", "httpd_sys_content_t")
  end

  it "explains that a basename is insufficient for expected-context lookup" do
    denial = double(details: { "target_evidence" => { "filesystem_paths" => [], "object_names" => ["basename"] } }, target_paths: [], permissions: ["read"], executable: nil)
    occurrence = double(normalized_denial: denial, occurred_at: Time.current)
    issue = double(permissions: ["read"], target_class: "file")

    result = described_class.call(issue: issue, occurrence: occurrence)

    expect(result[:missing_evidence]).to include("complete absolute target path from retained audit evidence; expected-context lookup was not run")
  end

  it "reports a failed asynchronous expected-context observation" do
    records = double
    allow(records).to receive(:where).with(record_type: [1400, 1107]).and_return([:avc])
    raw_event = double(file_context_observations: [{ "kind" => "expected_context", "path" => "/srv/file", "status" => "error", "reason" => "resolver_timeout" }], raw_audit_records: records)
    denial = double(details: { "target_evidence" => { "filesystem_paths" => ["/srv/file"], "object_names" => [] } }, target_paths: ["/srv/file"], permissions: ["read"], executable: nil)
    occurrence = double(normalized_denial: denial, raw_event: raw_event, occurred_at: Time.current)
    issue = double(permissions: ["read"], target_class: "file")

    result = described_class.call(issue: issue, occurrence: occurrence)

    expect(result[:observations].map { |item| item[:observation] }.join).to include("Expected file context", "resolver_timeout")
  end

  it "explains that multiple AVC records were not reduced to an arbitrary path lookup" do
    records = double
    allow(records).to receive(:where).with(record_type: [1400, 1107]).and_return([:avc, :user_avc])
    raw_event = double(file_context_observations: [], raw_audit_records: records)
    denial = double(details: { "target_evidence" => { "filesystem_paths" => ["/srv/a", "/srv/b"], "object_names" => ["a", "b"] } }, target_paths: ["/srv/a", "/srv/b"], permissions: ["read"], executable: nil)
    occurrence = double(normalized_denial: denial, raw_event: raw_event, occurred_at: Time.current)
    issue = double(permissions: ["read"], target_class: "file")

    result = described_class.call(issue: issue, occurrence: occurrence)

    expect(result[:missing_evidence]).to include("unambiguous absolute path-to-denied-object correlation; expected-context lookup was not run")
    expect(result[:missing_evidence]).to include("unambiguous AVC-to-path correlation; expected-context lookup was not run because the event contains multiple AVC records")
  end

  it "reports fleet correlations without claiming causation" do
    relation = double
    issue = double(permissions: [ "read" ], target_class: "file", occurrences: relation)
    allow(relation).to receive(:includes).with(:normalized_denial, :raw_event).and_return([])
    intelligence = { fleet: { current_configuration_hosts: 10, hosts_with_occurrence: 4, hosts_without_occurrence: 6, with_occurrence_modules: { [ "local_web", 400, "unknown" ] => 4 }, without_occurrence_modules: { [ "local_web", 400, "unknown" ] => 1, [ "baseline", 400, "unknown" ] => 2 } } }

    result = described_class.call(issue: issue, intelligence: intelligence)
    text = result[:observations].map { |observation| observation[:observation] }.join(" ")

    expect(text).to include("4 of 10", "present on 4/4 hosts with an occurrence", "1/6 hosts without", "baseline", "2/6 hosts without", "Investigate whether")
    expect(text).not_to include("caused", "causes")
  end
end
