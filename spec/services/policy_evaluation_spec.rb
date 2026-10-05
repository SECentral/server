require "rails_helper"

RSpec.describe PolicyEvaluation do
  include ActiveJob::TestHelper

  let(:organization) { Organization.create!(name: "policy-evaluation") }
  let(:identity) { "sha256:" + "a" * 64 }

  after do
    Occurrence.delete_all
    NormalizedDenial.delete_all
    PolicyFact.delete_all
    PolicyArtifact.delete_all
    Issue.delete_all
    RawEvent.delete_all
    HostSnapshot.delete_all
    AgentInstallation.delete_all
    Host.delete_all
    Organization.delete_all
    clear_enqueued_jobs
  end

  it "deduplicates equivalent occurrence questions and evaluator jobs" do
    artifact = "policy artifact"
    PolicyArtifact.create!(policy_identity: digest(artifact), artifact: artifact, artifact_size: artifact.bytesize)
    issue = create_issue("httpd_t", "port_t", "tcp_socket", [ "name_connect" ])
    events = 25.times.map do
      create_occurrence(issue, identity: digest(artifact), permissions: [ "name_connect" ]).raw_event
    end
    ids = events.map(&:id)

    expect {
      RequestPolicyFactsJob.perform_now(raw_event_ids: ids)
    }.to have_enqueued_job(EvaluatePolicyFactJob).exactly(1).times

    expect(PolicyFact.where(policy_identity: digest(artifact)).count).to eq(1)
  end

  it "does not reuse a question across exact policy identities" do
    issue = create_issue("httpd_t", "port_t", "tcp_socket", [ "name_connect" ])
    first = create_occurrence(issue, identity: identity, permissions: [ "name_connect" ])
    second = create_occurrence(issue, identity: "sha256:" + "b" * 64, permissions: [ "name_connect" ])

    PolicyFactRequest.for_event(first.raw_event)
    PolicyFactRequest.for_event(second.raw_event)

    expect(PolicyFact.pluck(:policy_identity)).to contain_exactly(identity, "sha256:" + "b" * 64)
  end

  it "keeps policy-rule facts separate from checkpoint boolean evaluation" do
    issue = create_issue("httpd_t", "unreserved_port_t", "tcp_socket", [ "name_connect" ])
    occurrence = create_occurrence(issue, identity: identity, permissions: [ "name_connect" ], booleans: [ { "name" => "httpd_can_network_connect", "current" => false, "status" => "observed" } ])
    rule = "allow httpd_t port_type:tcp_socket name_connect; [ httpd_can_network_connect ]:True"
    fact = create_fact(issue, "name_connect", status: "matched", matching_rules: [ rule ], rule_details: [ { "source_symbol" => "httpd_t", "target_symbol" => "port_type", "source_match" => "type", "target_match" => "attribute", "conditional_expression" => "httpd_can_network_connect", "conditional_branch" => "True" } ])

    evaluation = described_class.call(issue)
    diagnosis = IssueDiagnosis.call(issue, intelligence: { policy_evaluation: evaluation })

    expect(fact.reload).to have_attributes(status: "matched", matching_rules: [ rule ])
    expect(fact.rule_details.first).to include("conditional_expression" => "httpd_can_network_connect", "conditional_branch" => "True")
    expect(evaluation[:occurrence_evaluations].first).to include(rule_state: "conditional_inactive", policy_identity: [ identity ], checkpoint_observed_at: occurrence.raw_event.host_observed_at)
    expect(diagnosis).to include(kind: "conditional_allow_inactive", operation: "name_connect", policy_identity: identity, checkpoint_observed_at: occurrence.raw_event.host_observed_at)
    expect(occurrence.host_snapshot.details.dig("selinux", "booleans", 0, "current")).to be(false)
  end

  it "preserves alternative connect rules and evaluates 1,000 equivalent snapshot inputs once" do
    issue = create_issue("httpd_t", "unreserved_port_t", "tcp_socket", ["name_connect"])
    occurrence = create_occurrence(issue, identity: identity, permissions: ["name_connect"], booleans: [
      {"name" => "httpd_can_network_connect", "current" => false, "status" => "observed"},
      {"name" => "nis_enabled", "current" => false, "status" => "observed"}
    ])
    rules = ["allow httpd_t port_type:tcp_socket name_connect; [ httpd_can_network_connect ]:True", "allow nsswitch_domain unreserved_port_t:tcp_socket name_connect; [ nis_enabled ]:True"]
    create_fact(issue, "name_connect", status: "matched", matching_rules: rules)
    projection = Struct.new(:id, :host_id, :host_snapshot, :normalized_denial, :raw_event)
    inputs = 1_000.times.map { |index| projection.new(index + 1, occurrence.host_id, occurrence.host_snapshot, occurrence.normalized_denial, occurrence.raw_event) }
    allow(issue).to receive(:occurrences).and_return(inputs)
    expect(occurrence.raw_event).not_to receive(:host_snapshot)
    evaluator = described_class.new(issue)
    expect(evaluator).to receive(:evaluate_policy_context).once.and_call_original
    expect(PolicyFact).to receive(:where).once.and_call_original
    result = evaluator.call
    expect(result[:occurrence_evaluations].size).to eq(1_000)
    expect(result[:occurrence_evaluations]).to all(include(rule_state: "conditional_inactive"))
    expect(result[:conditional_rule_states].map { |rule| rule[:expression] }).to contain_exactly("httpd_can_network_connect", "nis_enabled")
    expect(result[:matching_rules]).to eq(rules)
    expect(PolicyFact.count).to eq(1)
  end

  it "preserves attribute-derived bind applicability for Scenario 003" do
    issue = create_issue("httpd_t", "unreserved_port_t", "tcp_socket", [ "name_bind" ])
    create_occurrence(issue, identity: identity, permissions: [ "name_bind" ], booleans: [ { "name" => "nis_enabled", "current" => false, "status" => "observed" } ])
    rule = "allow nsswitch_domain unreserved_port_t:tcp_socket name_bind; [ nis_enabled ]:True"
    create_fact(issue, "name_bind", status: "matched", matching_rules: [ rule ], rule_details: [ { "source_symbol" => "nsswitch_domain", "target_symbol" => "unreserved_port_t", "source_match" => "attribute", "target_match" => "type", "conditional_expression" => "nis_enabled", "conditional_branch" => "True" } ])

    evaluation = described_class.call(issue)
    diagnosis = IssueDiagnosis.call(issue, intelligence: { policy_evaluation: evaluation })

    expect(evaluation[:technical_evaluations].first["rule_details"]).to include(include("source_match" => "attribute", "source_symbol" => "nsswitch_domain"))
    expect(diagnosis).to include(kind: "conditional_allow_inactive", operation: "name_bind")
  end

  it "queries only the denied permission for Scenario 004 and supports exact no-match" do
    issue = create_issue("mysqld_t", "var_t", "file", [ "getattr" ])
    occurrence = create_occurrence(issue, identity: identity, permissions: [ "getattr" ])
    create_fact(issue, "getattr", status: "no_match", matching_rules: [])

    evaluation = described_class.call(issue)
    diagnosis = IssueDiagnosis.call(issue, intelligence: { policy_evaluation: evaluation })

    expect(PolicyFact.pluck(:permission)).to eq([ "getattr" ])
    expect(evaluation[:occurrence_evaluations].first).to include(rule_state: "no_matching_allow")
    expect(diagnosis).to include(kind: "no_matching_allow", permissions: [ "getattr" ], occurrence_id: occurrence.id)
  end

  it "supports Scenario 005 execute without supplementary questions" do
    issue = create_issue("httpd_t", "httpd_sys_content_t", "file", [ "execute" ])
    create_occurrence(issue, identity: identity, permissions: [ "execute" ], booleans: [
      { "name" => "httpd_builtin_scripting", "current" => true, "status" => "observed" },
      { "name" => "httpd_unified", "current" => false, "status" => "observed" },
      { "name" => "httpd_enable_cgi", "current" => true, "status" => "observed" }
    ], details: { "target_evidence" => { "filesystem_paths" => [ "/var/www/cgi-bin/helper" ], "object_names" => [] }, "enforcement_mode" => "enforcing", "syscall_evidence" => [ { "success" => "false" } ] })
    rule = "allow httpd_t httpdcontent:file { execute execute_no_trans getattr ioctl map open read }; [ ( httpd_builtin_scripting && httpd_unified && httpd_enable_cgi ) ]:True"
    create_fact(issue, "execute", status: "matched", matching_rules: [ rule ])

    evaluation = described_class.call(issue)
    diagnosis = IssueDiagnosis.call(issue, intelligence: { policy_evaluation: evaluation })

    expect(PolicyFact.pluck(:permission)).to eq([ "execute" ])
    expect(diagnosis).to include(kind: "conditional_allow_inactive", operation: "execute", path: "/var/www/cgi-bin/helper")
  end

  it "reports missing policy identity as unavailable without guessing a host policy" do
    issue = create_issue("httpd_t", "user_home_t", "file", [ "read" ])
    create_occurrence(issue, identity: nil, permissions: [ "read" ])

    evaluation = described_class.call(issue)

    expect(evaluation).to include(status: "unavailable")
    expect(evaluation[:occurrence_evaluations].first[:limitations]).to include("exact policy identity is unavailable")
    expect(PolicyFact.count).to eq(0)
  end

  it "reuses conditional-read work for one snapshot while preserving each event checkpoint and differing boolean state" do
    issue = create_issue("httpd_t", "user_home_t", "file", [ "read" ])
    first = create_occurrence(issue, identity: identity, permissions: [ "read" ], booleans: [ { "name" => "httpd_read_user_content", "current" => false, "status" => "observed" } ])
    event = first.raw_event.dup
    event.assign_attributes(audit_sequence: 2, evidence_digest: "second-read", host_observed_at: first.raw_event.host_observed_at + 10.seconds)
    event.save!
    denial = first.normalized_denial.dup
    denial.raw_event = event
    denial.save!
    repeated = first.dup
    repeated.assign_attributes(raw_event: event, normalized_denial: denial)
    repeated.save!
    active = create_occurrence(issue, identity: identity, permissions: [ "read" ], booleans: [ { "name" => "httpd_read_user_content", "current" => true, "status" => "observed" } ])
    rule = "allow httpd_t user_home_type:file { getattr ioctl lock open read }; [ httpd_read_user_content ]:True"
    create_fact(issue, "read", status: "matched", matching_rules: [ rule ])
    evaluator = described_class.new(issue)
    expect(evaluator).to receive(:evaluate_policy_context).exactly(2).times.and_call_original

    results = evaluator.call[:occurrence_evaluations].index_by { |item| item[:occurrence_id] }
    expect(results[first.id]).to include(rule_state: "conditional_inactive", checkpoint_observed_at: first.raw_event.host_observed_at)
    expect(results[repeated.id]).to include(rule_state: "conditional_inactive", checkpoint_observed_at: event.host_observed_at)
    expect(results[active.id]).to include(rule_state: "conditional_active")
    diagnosis = IssueDiagnosis.call(issue, intelligence: { policy_evaluation: { occurrence_evaluations: results.values } })
    expect(diagnosis).to include(kind: "conditional_allow_inactive", operation: "read", policy_identity: identity)
    expect(diagnosis[:next_step]).to include("intended to read files labeled user_home_t")
    expect(diagnosis[:next_step]).not_to include("enable", "relabel")
    expect(diagnosis[:condition_boolean_states].first).to include(expression: "httpd_read_user_content", state: "inactive")
    analyzer = IssueDiagnosis.new(issue, { policy_evaluation: { occurrence_evaluations: results.values } })
    expect(analyzer).to receive(:file_access_diagnosis).once.and_call_original
    summarized = analyzer.finding_summaries
    expect(summarized.first[:occurrence_count]).to eq(2)
  end

  it "does not describe an unconditional read allow or an unknown boolean as an inactive conditional path" do
    issue = create_issue("httpd_t", "user_home_t", "file", [ "read" ])
    occurrence = create_occurrence(issue, identity: identity, permissions: [ "read" ])
    fact = create_fact(issue, "read", status: "matched", matching_rules: [ "allow httpd_t user_home_type:file read; [ httpd_read_user_content ]:True" ])
    evaluation = described_class.call(issue)
    expect(evaluation[:occurrence_evaluations].first[:rule_state]).to eq("unknown")
    expect(IssueDiagnosis.call(issue, intelligence: { policy_evaluation: evaluation })).to be_nil
    occurrence.host_snapshot.update!(details: occurrence.host_snapshot.details.deep_merge("selinux" => { "booleans" => [ { "name" => "httpd_read_user_content", "current" => false, "status" => "observed" } ] }))
    fact.update!(matching_rules: fact.matching_rules + [ "allow httpd_t user_home_type:file read;" ])
    expect(IssueDiagnosis.call(issue, intelligence: { policy_evaluation: described_class.call(issue) })).to be_nil
  end

  private

  def digest(bytes)
    "sha256:#{Digest::SHA256.hexdigest(bytes)}"
  end

  def create_issue(source, target, object_class, permissions)
    organization.issues.create!(fingerprint_version: 3, fingerprint_digest: SecureRandom.hex(16), source_type: source,
      target_type: target, target_class: object_class, permissions: permissions, first_seen_at: Time.current, last_seen_at: Time.current)
  end

  def create_occurrence(issue, identity:, permissions:, booleans: [], details: {})
    host = organization.hosts.create!(external_id: SecureRandom.hex(16), hostname: "policy-test", last_seen_at: Time.current)
    selinux = { "booleans" => booleans }
    selinux["policy_identity"] = identity if identity
    snapshot = host.host_snapshots.create!(details: { "selinux" => selinux })
    installation = organization.agent_installations.create!(name: "agent-#{SecureRandom.hex(4)}", bound_host: host)
    sequence = RawEvent.count + 1
    timestamp = Time.current
    event = organization.raw_events.create!(agent_installation: installation, host: host, host_snapshot: snapshot, host_observed_at: timestamp - 1.minute,
      audit_timestamp: timestamp, audit_sequence: sequence, boot_id: "boot-#{host.external_id}", completion_reason: "eoe",
      evidence_digest: SecureRandom.hex(16), agent_received_at: timestamp, server_received_at: timestamp, schema_version: 3)
    denial = event.normalized_denials.create!(ordinal: 0, normalization_version: 1, status: "ok", source_type: issue.source_type,
      target_type: issue.target_type, target_class: issue.target_class, permissions: permissions,
      details: { "enforcement_mode" => "enforcing", "target_evidence" => { "filesystem_paths" => [], "object_names" => [] } }.merge(details))
    Occurrence.create!(organization: organization, host: host, host_snapshot: snapshot, raw_event: event,
      normalized_denial: denial, issue: issue, occurred_at: timestamp)
  end

  def create_fact(issue, permission, status:, matching_rules:, rule_details: [])
    PolicyFact.create!(policy_identity: identity, query_kind: PolicyFact::QUERY_KIND, source_type: issue.source_type,
      target_type: issue.target_type, object_class: issue.target_class,
      permission: permission, status: status, matching_rules: matching_rules, rule_details: rule_details,
      evaluator_version: "sesearch-4.4.4", evaluated_at: Time.current)
  end
end
