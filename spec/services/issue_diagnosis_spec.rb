require "rails_helper"

RSpec.describe IssueDiagnosis do
  let(:issue) { instance_double(Issue, source_type: "httpd_t", target_type: "user_home_t", target_class: "file", permissions: ["read", "open"]) }

  def intelligence(observations)
    { expected_context_observations: observations }
  end

  def observation(path: "/var/www/html/secentral-test.html", host_id: 1, observed_context: "unconfined_u:object_r:user_home_t:s0", expected_context: "system_u:object_r:httpd_sys_content_t:s0", status: "resolved", occurrence_id: 101)
    {
      "path" => path, "object_class" => "file", "file_type" => "file", "status" => status,
      "expected_context" => expected_context, "observed_at" => "2026-09-25T10:05:01Z",
      "resolver" => "matchpathcon", "reason" => ("resolver_timeout" if status == "error"),
      "target_context" => observed_context, "target_class" => "file", "filesystem_paths" => [path], "permissions" => ["read"],
      host_id: host_id, occurrence_id: occurrence_id, raw_event_id: 500,
      avc_occurred_at: Time.iso8601("2026-09-25T10:05:00Z")
    }.compact
  end

  it "compares the AVC target type with the later expected-context result" do
    result = described_class.call(issue, intelligence: intelligence([observation]))

    expect(result).to include(kind: "file_context_mismatch", evidence_strength: "moderate", path: "/var/www/html/secentral-test.html", observed_type: "user_home_t", expected_type: "httpd_sys_content_t", file_type: "file")
    expect(result).to include(observed_context: "unconfined_u:object_r:user_home_t:s0", expected_context: "system_u:object_r:httpd_sys_content_t:s0", expected_context_observed_at: "2026-09-25T10:05:01Z")
    expect(result[:interpretation]).to include("may help explain")
    expect(result[:limitation]).to include("does not prove the same configuration applied at AVC time")
    expect(result[:next_step]).to include("appropriate for the workload")
    expect(result[:permissions]).to eq(["read"])
    expect(result[:evidence].last[:fact]).not_to include("open")
  end

  it "provides safely escaped label checks for a qualifying absolute path" do
    issue = instance_double(Issue, source_type: "httpd_t", target_type: "user_home_t", target_class: "file", permissions: ["read"])
    result = IssueLabelingGuidance.call(issue, paths: ["/var/www/html/a file.txt"])

    expect(result).to include(type: "probable_label_mismatch", path: "/var/www/html/a file.txt", observed_type: "user_home_t", conventional_type: "httpd_sys_content_t")
    expect(result[:commands].map { |command| command[:command] }).to eq([
      "matchpathcon -- /var/www/html/a\\ file.txt",
      "restorecon -v -- /var/www/html/a\\ file.txt",
      "restorecon -Rv -- /var/www/html"
    ])
  end

  it "omits commands when there is no qualifying absolute path or type" do
    issue = instance_double(Issue, source_type: "httpd_t", target_type: "user_home_t", target_class: "file", permissions: ["read"])
    expect(IssueLabelingGuidance.call(issue, paths: ["relative.txt", "/var/www/../home/file"])).to be_nil
    expect(IssueLabelingGuidance.call(issue, paths: ["/home/file"])).to be_nil
  end

  it "does not report a mismatch when the types agree" do
    current = "unconfined_u:object_r:user_home_t:s0"
    expected = "system_u:object_r:user_home_t:s0"
    expect(described_class.call(issue, intelligence: intelligence([observation(observed_context: current, expected_context: expected)]))).to be_nil
  end

  it "does not report a mismatch for a SELinux user-only context difference" do
    current = "unconfined_u:object_r:user_home_t:s0"
    expected = "system_u:object_r:user_home_t:s0"
    expect(described_class.call(issue, intelligence: intelligence([observation(observed_context: current, expected_context: expected)]))).to be_nil
  end

  it "does not report a mismatch without a resolved expected context" do
    expect(described_class.call(issue, intelligence: intelligence([observation(status: "unavailable", expected_context: nil)]))).to be_nil
  end

  it "does not call an earlier expected-context sample post-AVC evidence" do
    sample = observation.merge("observed_at" => "2026-09-25T10:04:59Z")
    expect(described_class.call(issue, intelligence: intelligence([sample]))).to be_nil
  end

  it "requires the observed absolute path to be present in the AVC evidence" do
    evidence = observation.merge("filesystem_paths" => [])
    expect(described_class.call(issue, intelligence: intelligence([evidence]))).to be_nil
  end

  it "suppresses conflicting multi-host evidence" do
    evidence = [observation, observation(host_id: 2, expected_context: "system_u:object_r:var_t:s0")]

    expect(described_class.call(issue, intelligence: intelligence(evidence))).to be_nil
  end

  it "preserves the event-associated limitation" do
    result = described_class.call(issue, intelligence: intelligence([observation]))

    expect(result[:limitation]).to include("inspected after the AVC")
    expect(result[:temporal_scope]).to eq("avc_vs_expected_context_inspection")
  end

  it "leaves unknown types without guessed descriptions" do
    custom_issue = instance_double(Issue, source_type: "httpd_t", target_type: "custom_content_t", target_class: "file", permissions: ["read", "open"])
    result = described_class.call(custom_issue, intelligence: intelligence([observation(observed_context: "unconfined_u:object_r:custom_content_t:s0", expected_context: "system_u:object_r:other_content_t:s0")]))

    expect(result).to include(observed_type: "custom_content_t", expected_type: "other_content_t")
  end

  it "produces an enforcing conditional-allow finding from one occurrence" do
    result = described_class.call(policy_issue, intelligence: policy_intelligence(policy_evaluation_item("conditional_inactive", false)))

    expect(result).to include(kind: "conditional_allow_inactive", occurrence_id: 12266, enforcement_mode: "enforcing", syscall_failed: true)
    expect(result[:title]).to eq("SELinux blocked a network connection request")
    expect(result[:source_description]).to eq("httpd_t")
    expect(result[:next_step]).to include("Confirm whether this workload is expected")
  end

  it "renders a conditional bind finding from occurrence-scoped bind evidence" do
    result = described_class.call(bind_policy_issue(issue_permissions: %w[name_bind name_connect]), intelligence: policy_intelligence(policy_evaluation_item("conditional_inactive", false)))

    expect(result).to include(kind: "conditional_allow_inactive", operation: "name_bind", permission: "name_bind", bind_port: "12345", syscall_failed: true)
    expect(result).not_to have_key(:destination_port)
    expect(result[:title]).to eq("SELinux blocked a local port bind request")
    expect(result[:title]).not_to include("connect")
    expect(result[:next_step]).to include("bind TCP port 12345")
    expect(result[:next_step]).not_to include("enable")
    expect(result[:evidence].first[:fact]).to include("attempted name_bind")
    expect(result[:evidence].first[:fact]).not_to include("name_connect")
  end

  it "does not produce connection wording for an unsupported network operation" do
    result = described_class.call(policy_issue(permissions: ["recvfrom"]), intelligence: policy_intelligence(policy_evaluation_item("conditional_inactive", false)))

    expect(result).to be_nil
  end

  it "produces an enforcing execute conditional-allow finding with occurrence path evidence" do
    result = described_class.call(execute_policy_issue, intelligence: policy_intelligence(execute_evaluation("conditional_inactive")))

    expect(result).to include(kind: "conditional_allow_inactive", operation: "execute", path: "/var/www/cgi-bin/secentral-s005-helper.sh", enforcement_mode: "enforcing", syscall_failed: true)
    expect(result[:title]).to eq("SELinux blocked an execution request")
    expect(result[:next_step]).to include("expected to execute this file")
    expect(result[:next_step]).not_to include("enable")
  end

  it "does not say permissive execute AVCs were blocked" do
    result = described_class.call(execute_policy_issue(permissive: true), intelligence: policy_intelligence(execute_evaluation("conditional_inactive", permissive: true)))

    expect(result[:title]).to include("reported")
    expect(result[:title]).not_to include("blocked")
    expect(result[:finding]).to include("reported")
    expect(result[:finding]).not_to include("blocked")
    expect(result[:syscall_failed]).to be false
  end

  it "does not diagnose an active execute conditional relationship" do
    expect(described_class.call(execute_policy_issue, intelligence: policy_intelligence(execute_evaluation("conditional_active")))).to be_nil
  end

  it "uses no-matching-allow semantics for execute with no matching allow" do
    result = described_class.call(execute_policy_issue, intelligence: policy_intelligence(execute_evaluation("no_matching_allow", result: "no_match")))

    expect(result).to include(kind: "no_matching_allow")
  end

  it "does not use inactive execute_no_trans as the execute diagnosis" do
    item = execute_evaluation("conditional_inactive", result: "no_match")
    item[:evaluations] << { "permissions" => ["execute_no_trans"], "result" => "matched" }

    result = described_class.call(execute_policy_issue, intelligence: policy_intelligence(item))
    expect(result).to be_nil
  end

  it "does not use transition or entrypoint relationships as the execute diagnosis" do
    %w[possible_domain_transition process_transition destination_entrypoint].each do |relationship|
      item = execute_evaluation("no_matching_allow", result: "no_match")
      item[:execution_policy] = { relationships: [{ relationship: relationship, state: "conditional_inactive" }] }

      expect(described_class.call(execute_policy_issue, intelligence: policy_intelligence(item))).to include(kind: "no_matching_allow")
    end
  end

  it "falls back without inventing a path when only a basename is observed" do
    result = described_class.call(execute_policy_issue(paths: [], names: ["secentral-s005-helper.sh"]), intelligence: policy_intelligence(execute_evaluation("conditional_inactive")))

    expect(result).not_to have_key(:path)
    expect(result[:evidence].first[:fact]).to include("secentral-s005-helper.sh")
    expect(result[:evidence].first[:fact]).not_to include("/")
  end

  it "uses the technical source domain" do
    result = described_class.call(policy_issue("vendor_custom_t"), intelligence: policy_intelligence(policy_evaluation_item("conditional_inactive", false, 12266, "vendor_custom_t")))

    expect(result[:title]).to eq("SELinux blocked a network connection request")
    expect(result[:source_description]).to eq("vendor_custom_t")
  end

  it "does not translate observed process evidence into an application identity" do
    result = described_class.call(policy_issue(process_evidence: { "commands" => ["httpd"] }), intelligence: policy_intelligence(policy_evaluation_item("conditional_inactive", false)))

    expect(result[:title]).to eq("SELinux blocked a network connection request")
    expect(result[:source_description]).to eq("httpd_t")
  end

  it "keeps all boolean inputs attached to a compound expression" do
    item = policy_evaluation_item("conditional_inactive", false)
    item[:conditional_rule_states][0][:expression] = "first_boolean || second_boolean"
    item[:booleans] = [{ "name" => "first_boolean", "current" => false, "status" => "observed" }, { "name" => "second_boolean", "current" => true, "status" => "observed" }]
    result = described_class.call(policy_issue, intelligence: policy_intelligence(item))

    expect(result[:condition_boolean_states].first[:booleans].map { |boolean| boolean["name"] }).to eq(%w[first_boolean second_boolean])
  end

  it "does not call a permissive AVC blocked" do
    result = described_class.call(policy_issue, intelligence: policy_intelligence(policy_evaluation_item("conditional_inactive", true)))

    expect(result[:title]).to include("reported")
    expect(result[:title]).not_to include("blocked")
    expect(result[:evidence].last[:fact]).to include("would be denied under enforcement")
  end

  it "suppresses policy findings without an inactive conditional allow" do
    %w[no_matching_allow unconditional_match conditional_active unknown].each do |state|
      result = described_class.call(policy_issue, intelligence: policy_intelligence(policy_evaluation_item(state, false)))

      expect(result).to be_nil
    end
  end

  it "produces an occurrence-scoped no-matching-allow finding" do
    result = described_class.call(file_policy_issue, intelligence: policy_intelligence(no_matching_file_evaluation))

    expect(result).to include(kind: "no_matching_allow", occurrence_id: 12282, source_description: "mysqld_t", permissions: ["read"])
    expect(result[:title]).to eq("No matching SELinux allow was found for this access")
    expect(result[:lead]).to include("SELinux domain mysqld_t", "denied read access to a file labeled var_t", "no matching allow for the denied read access")
    expect(result[:lead]).not_to include("MariaDB")
    expect(result[:next_step]).to include("Identify and confirm the full path for plugin.frm")
    expect(result[:limitation]).to include("wrong target label", "custom policy")
    expect(result[:policy_guidance]).not_to include("domain_can_mmap_files", "mysqld_db_t")
  end

  it "checks that a process is configured to use an observed path before suggesting label investigation" do
    result = described_class.call(file_policy_issue(paths: ["/srv/database/ibdata1"], command: "mariadbd"), intelligence: policy_intelligence(no_matching_file_evaluation))

    expect(result[:next_step]).to include("mariadbd is configured to access /srv/database/ibdata1", "access is intended")
  end

  it "explains a denied local bind using its recorded port, domain and label" do
    result = described_class.call(no_allow_network_issue, intelligence: policy_intelligence(no_matching_network_evaluation("name_bind")))

    expect(result).to include(kind: "no_matching_allow", operation: "name_bind", bind_port: "9090")
    expect(result).not_to have_key(:destination_port)
    expect(result[:title]).to eq("httpd (httpd_t) was denied binding to TCP port 9090")
    expect(result[:lead]).to include("labeled websm_port_t", "does not allow httpd_t to bind to ports with that label")
    expect(result[:next_step]).to include("listen on TCP port 9090", "service configuration and SELinux port mapping", "does not establish that the port label should change")
    expect(result[:next_step]).not_to include("object path")
  end

  it "distinguishes outbound connections from local binding even in permissive mode" do
    item = no_matching_network_evaluation("name_connect").merge(enforcement_mode: "permissive")
    result = described_class.call(no_allow_network_issue(operation: "name_connect"), intelligence: policy_intelligence(item))

    expect(result).to include(operation: "name_connect", destination_port: "9090", syscall_failed: false)
    expect(result).not_to have_key(:bind_port)
    expect(result[:title]).to include("denied connecting to TCP port 9090")
    expect(result[:title]).not_to include("blocked")
    expect(result[:lead]).to include("connect to ports with that label")
    expect(result[:next_step]).not_to include("listen")
  end

  it "does not select a port from missing or ambiguous occurrence evidence" do
    [[], ["9090", "9091"]].each do |ports|
      result = described_class.call(no_allow_network_issue(ports: ports), intelligence: policy_intelligence(no_matching_network_evaluation("name_bind")))

      expect(result).not_to have_key(:bind_port)
      expect(result[:title]).to include("port (number not recorded unambiguously)")
      expect(result[:title]).not_to include("9090")
    end
  end

  def no_allow_network_issue(operation: "name_bind", ports: ["9090"])
    denial = instance_double(NormalizedDenial, source_type: "httpd_t", target_type: "websm_port_t", target_class: "tcp_socket",
      permissions: [operation], command: "httpd", details: { "network_evidence" => { (operation == "name_bind" ? "bind_port_fields" : "dest_fields") => ports } })
    occurrence = instance_double(Occurrence, id: 12266, normalized_denial: denial)
    instance_double(Issue, source_type: "httpd_t", target_type: "websm_port_t", target_class: "tcp_socket", permissions: [operation], occurrences: [occurrence])
  end

  def no_matching_network_evaluation(operation)
    { status: "evaluated", occurrence_id: 12266, policy_identity: ["sha256:policy"], rule_state: "no_matching_allow", enforcement_mode: "enforcing",
      evaluations: [{ "permissions" => [operation], "result" => "no_match" }] }
  end

  it "does not collapse mixed observed permission states into one finding" do
    item = no_matching_file_evaluation
    item[:evaluations] << { "permissions" => ["open"], "result" => "matched" }
    item[:rule_state] = "conditional_inactive"

    expect(described_class.call(file_policy_issue(permissions: %w[read open]), intelligence: policy_intelligence(item))).to be_nil
  end

  it "prefers the enforcing occurrence when an issue has mixed enforcement states" do
    permissive = policy_evaluation_item("conditional_inactive", true, 12265)
    enforcing = policy_evaluation_item("conditional_inactive", false, 12266)
    result = described_class.call(mixed_policy_issue, intelligence: policy_intelligence([permissive, enforcing]))

    expect(result).to include(occurrence_id: 12266, enforcement_mode: "enforcing")
  end

  def policy_issue(source_type = "httpd_t", process_evidence: {}, permissions: ["name_connect"])
    denial = policy_denial(12266, false, source_type, process_evidence, permissions)
    occurrence = instance_double(Occurrence, id: 12266, normalized_denial: denial)
    instance_double(Issue, source_type: source_type, target_type: "unreserved_port_t", target_class: "tcp_socket", permissions: permissions, occurrences: [occurrence])
  end

  def execute_policy_issue(permissive: false, paths: ["/var/www/cgi-bin/secentral-s005-helper.sh"], names: [])
    denial = instance_double(NormalizedDenial, source_type: "httpd_t", target_type: "httpd_sys_content_t", target_class: "file", permissions: ["execute"], details: { "target_evidence" => { "filesystem_paths" => paths, "object_names" => names }, "process_evidence" => { "commands" => ["httpd"], "executables" => ["/usr/sbin/httpd"] }, "syscall_evidence" => [{ "syscall" => "execve", "success" => permissive ? "false" : "false", "exit" => "-13" }], "enforcement_mode" => permissive ? "permissive" : "enforcing" })
    occurrence = instance_double(Occurrence, id: 12267, normalized_denial: denial)
    instance_double(Issue, source_type: "httpd_t", target_type: "httpd_sys_content_t", target_class: "file", permissions: ["execute"], occurrences: [occurrence])
  end

  def execute_evaluation(state, permissive: false, result: "matched")
    condition_state = state == "conditional_active" ? "active" : "inactive"
    { status: "evaluated", occurrence_id: 12267, policy_identity: ["sha256:policy"], rule_state: state, enforcement_mode: permissive ? "permissive" : "enforcing", permissive: permissive, evaluations: [{ "permissions" => ["execute"], "result" => result, "matching_rules" => ["allow httpd_t httpd_sys_content_t:file execute; [ httpd_builtin_scripting && httpd_unified && httpd_enable_cgi ]:True"] }], conditional_rule_states: [{ expression: "httpd_builtin_scripting && httpd_unified && httpd_enable_cgi", rule: "allow httpd_t httpd_sys_content_t:file execute; [ httpd_builtin_scripting && httpd_unified && httpd_enable_cgi ]:True", state: condition_state }], booleans: [{ "name" => "httpd_builtin_scripting", "current" => true, "status" => "observed" }, { "name" => "httpd_unified", "current" => false, "status" => "observed" }, { "name" => "httpd_enable_cgi", "current" => true, "status" => "observed" }] }
  end

  def file_policy_issue(permissions: ["read"], paths: [], command: nil)
    target_evidence = { "object_names" => ["plugin.frm"], "filesystem_paths" => paths }
    denial = instance_double(NormalizedDenial, source_type: "mysqld_t", target_type: "var_t", target_class: "file", permissions: permissions,
      command: command, details: { "target_evidence" => target_evidence, "process_evidence" => { "commands" => ["mariadbd"], "executables" => ["/usr/libexec/mariadbd"] }, "enforcement_mode" => "enforcing" })
    occurrence = instance_double(Occurrence, id: 12282, normalized_denial: denial)
    instance_double(Issue, source_type: "mysqld_t", target_type: "var_t", target_class: "file", permissions: permissions, occurrences: [occurrence])
  end

  def no_matching_file_evaluation
    { status: "evaluated", occurrence_id: 12282, policy_identity: ["sha256:policy"], rule_state: "no_matching_allow", evaluations: [{ "permissions" => ["read"], "result" => "no_match" }] }
  end

  def bind_policy_issue(issue_permissions: ["name_bind"])
    denial = policy_denial(12266, false, "httpd_t", {}, ["name_bind"], { "bind_port_fields" => ["12345"] })
    occurrence = instance_double(Occurrence, id: 12266, normalized_denial: denial)
    instance_double(Issue, source_type: "httpd_t", target_type: "unreserved_port_t", target_class: "tcp_socket", permissions: issue_permissions, occurrences: [occurrence])
  end

  def mixed_policy_issue
    occurrences = [instance_double(Occurrence, id: 12265, normalized_denial: policy_denial(12265, true)), instance_double(Occurrence, id: 12266, normalized_denial: policy_denial(12266, false))]
    instance_double(Issue, source_type: "httpd_t", target_type: "unreserved_port_t", target_class: "tcp_socket", permissions: ["name_connect"], occurrences: occurrences)
  end

  def policy_denial(id, permissive, source_type = "httpd_t", process_evidence = {}, permissions = ["name_connect"], network = { "dest_fields" => ["12345"] })
    instance_double(NormalizedDenial, source_type: source_type, target_type: "unreserved_port_t", target_class: "tcp_socket", permissions: permissions, details: { "network_evidence" => network, "process_evidence" => process_evidence, "syscall_evidence" => [{ "success" => "no" }], "enforcement_mode" => permissive ? "permissive" : "enforcing" })
  end

  def policy_intelligence(evaluations)
    { policy_evaluation: { occurrence_evaluations: evaluations.is_a?(Array) ? evaluations : [evaluations] } }
  end

  def policy_evaluation_item(state, permissive, occurrence_id = 12266, source_type = "httpd_t")
    { status: "evaluated", occurrence_id: occurrence_id, policy_identity: ["sha256:policy"], rule_state: state, enforcement_mode: permissive ? "permissive" : "enforcing", permissive: permissive, conditional_rule_states: [{ expression: "httpd_can_network_connect", rule: "allow #{source_type} ... [ httpd_can_network_connect ]:True", state: "inactive" }], booleans: [{ "name" => "httpd_can_network_connect", "current" => false, "status" => "observed", "description" => "Allow HTTPD scripts and modules to connect to the network using TCP." }] }
  end
end
