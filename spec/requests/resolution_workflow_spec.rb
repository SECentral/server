require "rails_helper"

RSpec.describe "Evidence-driven resolution workflow", type: :request do
  around do |example|
    ActiveRecord::Base.transaction do
      example.run
      raise ActiveRecord::Rollback
    end
  end
  before { sign_in_operator }

  def fixture(network: true, path: "/var/www/html/test file;$(id)", organization: nil, issue: nil)
    org = organization || Organization.find_or_create_by!(name: "resolution")
    issue ||= Issue.create!(organization: org, fingerprint_version: 4, fingerprint_digest: SecureRandom.hex,
      source_type: "httpd_t", target_type: network ? "unreserved_port_t" : "user_home_t", target_class: network ? "tcp_socket" : "file",
      permissions: [network ? "name_connect" : "entrypoint"], first_seen_at: Time.current, last_seen_at: Time.current)
    host = Host.create!(organization: org, external_id: SecureRandom.hex, hostname: "web-1", last_seen_at: Time.current)
    agent = AgentInstallation.create!(organization: org, name: "test-agent")
    identity = "sha256:#{SecureRandom.hex(32)}"
    snapshot = HostSnapshot.create!(host: host, details: { "boot_id" => "boot", "selinux" => { "policy_identity" => identity,
      "booleans" => %w[httpd_can_network_connect nis_enabled].map { |name| { "name" => name, "status" => "observed", "current" => false } } } })
    host.host_snapshot_observations.create!(agent_installation: agent, host_snapshot: snapshot,
      first_observed_at: Time.current, last_observed_at: Time.current, first_received_at: Time.current, last_received_at: Time.current)
    raw = RawEvent.create!(organization: org, host: host, agent_installation: agent, host_snapshot: snapshot,
      audit_timestamp: 1.minute.ago, audit_sequence: 1, boot_id: "boot", completion_reason: "eoe", evidence_digest: "test",
      schema_version: 2, host_observed_at: 2.minutes.ago, agent_received_at: Time.current, server_received_at: Time.current,
      file_context_observations: network ? [] : [{ "kind" => "expected_context", "path" => path, "object_class" => "file", "file_type" => "file", "status" => "resolved",
        "expected_context" => "system_u:object_r:httpd_sys_content_t:s0", "observed_at" => Time.current.iso8601(6), "resolver" => "matchpathcon" }])
    denial = NormalizedDenial.create!(raw_event: raw, normalization_version: 1, ordinal: 0, status: "ok", source_type: issue.source_type,
      target_type: issue.target_type, target_class: issue.target_class, permissions: issue.permissions, command: network ? "httpd" : "runcon",
      target_context: "system_u:object_r:#{issue.target_type}:s0", details: { "enforcement_mode" => "enforcing",
        "target_evidence" => { "filesystem_paths" => network ? [] : [path] }, "network_evidence" => { "dest_fields" => ["12345"] },
        "syscall_evidence" => [{ "success" => "no" }] })
    occurrence = Occurrence.create!(organization: org, issue: issue, host: host, host_snapshot: snapshot, raw_event: raw, normalized_denial: denial, occurred_at: raw.audit_timestamp)
    if network
      PolicyFact.create!(policy_identity: identity, query_kind: "allow", source_type: issue.source_type, target_type: issue.target_type,
        object_class: issue.target_class, permission: "name_connect", status: "matched", evaluator_version: "4.5.1",
        matching_rules: ["allow httpd_t port_type:tcp_socket name_connect; [ httpd_can_network_connect ]:True",
          "allow nsswitch_domain unreserved_port_t:tcp_socket name_connect; [ nis_enabled ]:True"])
    end
    [issue, occurrence, host, snapshot]
  end

  def workflow(issue)
    get "/api/v1/issues/#{issue.id}/resolutions"
    expect(response).to have_http_status(:ok)
    JSON.parse(response.body)
  end

  def home_content_fixture(path: nil)
    issue, occurrence, host, snapshot = fixture(network: false, path: path)
    issue.update!(permissions: ["read"])
    occurrence.normalized_denial.update!(permissions: ["read"], details: {
      "enforcement_mode" => "enforcing", "syscall_evidence" => [{ "success" => "no" }],
      "target_evidence" => { "filesystem_paths" => [path].compact, "object_names" => ["report.html"] }
    })
    occurrence.raw_event.update!(file_context_observations: [])
    snapshot.update!(details: snapshot.details.deep_merge("selinux" => {
      "booleans" => [{ "name" => "httpd_read_user_content", "current" => false, "status" => "observed" }]
    }))
    PolicyFact.create!(policy_identity: snapshot.details.dig("selinux", "policy_identity"), query_kind: "allow", source_type: "httpd_t",
      target_type: "user_home_t", object_class: "file", permission: "read", status: "matched", evaluator_version: "test",
      matching_rules: ["allow httpd_t user_home_t:file read; [ httpd_read_user_content ]:True"])
    [issue, occurrence, host, snapshot]
  end

  it "keeps home-content Boolean changes secondary and requires a path and explicit home-content review on the server" do
    issue, _, host, = home_content_fixture
    candidate = workflow(issue).fetch("candidates").sole
    expect(candidate).to include("requires_home_content_review" => true, "presentation" => "technical_alternative", "home_content_path" => nil)
    params = { candidate_id: candidate.fetch("id"), evidence_version: candidate.fetch("evidence_version") }
    [nil, { path: "/home/alice/report.html", confirmed: false }, { path: "report.html", confirmed: true },
      { path: "/home/alice/../report.html", confirmed: true }, { path: "/home/alice/wrong.html", confirmed: true }].each do |review|
      mutate("/api/v1/issues/#{issue.id}/resolution-intent", **params, home_content_review: review)
      expect(response).to have_http_status(:conflict)
      expect(ResolutionIntent.where(issue: issue)).to be_empty
    end
    review = { path: "/srv/custom-home/alice/report.html", confirmed: true }
    mutate("/api/v1/issues/#{issue.id}/resolution-intent", **params, home_content_review: review)
    expect(response).to have_http_status(:ok)
    intent = ResolutionIntent.find_by!(issue: issue)
    expect(intent.evidence_basis["home_content_review"]).to eq(review.stringify_keys.merge("host_id" => host.id))
    expect(workflow(issue)).to include("freshness" => "current", "change_plan" => include("evidence_basis" => include("home_content_review" => include("path" => review[:path]))))
    intent.update!(evidence_basis: intent.evidence_basis.except("home_content_review"))
    expect(workflow(issue)).to include("freshness" => "evidence_changed", "change_plan" => nil)
  end

  it "requires the home-content review path to match a retained absolute path" do
    issue, = home_content_fixture(path: "/home/alice/report.html")
    candidate = workflow(issue).fetch("candidates").sole
    mutate("/api/v1/issues/#{issue.id}/resolution-intent", candidate_id: candidate["id"], evidence_version: candidate["evidence_version"],
      home_content_review: { path: "/srv/custom-home/alice/report.html", confirmed: true })
    expect(response).to have_http_status(:conflict)
    expect(ResolutionIntent.where(issue: issue)).to be_empty
  end

  def mutate(path, method: :patch, **params)
    token = response.headers["X-CSRF-Token"]
    public_send(method, path, params: params.to_json, headers: { "Content-Type" => "application/json", "X-CSRF-Token" => token })
  end

  def select_candidate(issue, path: nil, boolean: nil)
    candidate = workflow(issue)["candidates"].find do |item|
      (!path || item.dig("evidence_basis", "path") == path) && (!boolean || item.dig("evidence_basis", "boolean") == boolean)
    end
    mutate("/api/v1/issues/#{issue.id}/resolution-intent", candidate_id: candidate["id"], evidence_version: candidate["evidence_version"])
    expect(response).to have_http_status(:ok)
    ResolutionIntent.find_by!(issue: issue)
  end

  # Real ingestion/normalization and, for files, the authoritative observation boundary.
  def ingest_equivalent(issue, reference, path: nil, expected_context: "system_u:object_r:httpd_sys_content_t:s0")
    issue.update!(fingerprint_digest: FingerprintV4.call(issue.attributes.symbolize_keys).fetch(:digest))
    host = reference.host
    observed = reference.raw_event.host_observed_at
    host.host_snapshot_observations.first.update!(first_observed_at: observed, last_observed_at: Time.current)
    sequence = host.raw_events.maximum(:audit_sequence) + 1
    timestamp = issue.last_seen_at + 5.seconds
    target = path ? "path=\"#{path}\"" : "dest=12345"
    avc = "type=AVC msg=audit(#{timestamp.to_f}:#{sequence}): avc: denied { #{issue.permissions.join(' ')} } for pid=42 comm=\"#{path ? 'runcon' : 'httpd'}\" #{target} scontext=system_u:system_r:#{issue.source_type}:s0 tcontext=#{reference.normalized_denial.target_context} tclass=#{issue.target_class} permissive=0"
    payload = { "schema_version" => 4, "agent" => { "version" => "semantic-test" }, "host_id" => host.external_id,
      "boot_id" => reference.raw_event.boot_id, "host_observed_at" => observed.iso8601(6), "events" => [{ "category" => "avc",
        "audit_event" => { "timestamp" => timestamp.iso8601(6), "sequence" => sequence }, "agent_received_at" => timestamp.iso8601(6),
        "completion_reason" => "eoe", "records" => [{ "position" => 0, "type" => 1400, "type_name" => "AVC",
          "timestamp" => timestamp.iso8601(6), "sequence" => sequence, "payload" => Base64.strict_encode64(avc) }] }] }
    raw = IngestEvents.new(organization: issue.organization, payload: payload).call.sole
    ProcessRawEvent.call(raw)
    occurrence = raw.occurrences.sole
    expect(occurrence.issue_id).to eq(issue.id)
    expect(occurrence.host_snapshot_id).to eq(reference.host_snapshot_id)
    if path
      PersistExpectedContextObservation.call(organization: issue.organization, payload: {
        "schema_version" => 1, "agent" => { "version" => "semantic-test" }, "host_id" => host.external_id,
        "boot_id" => raw.boot_id, "host_observed_at" => observed.iso8601(6),
        "audit_event" => { "timestamp" => raw.audit_timestamp.iso8601(6), "sequence" => raw.audit_sequence },
        "observation" => { "path" => path, "object_class" => "file", "file_type" => "file", "status" => "resolved",
          "expected_context" => expected_context, "observed_at" => (timestamp + 1.second).iso8601(6), "resolver" => "matchpathcon" }
      })
    end
    occurrence
  end

  context "candidate-semantic reviewed-plan freshness" do
    it "uses bind-port evidence in the latest access diagram rather than a destination field" do
      issue, occurrence, = fixture
      issue.update!(permissions: ["name_bind"])
      occurrence.normalized_denial.update!(permissions: ["name_bind"], details: {
        "network_evidence" => { "dest_fields" => ["9999"], "bind_port_fields" => ["12345"] }
      })
      expect(workflow(issue).fetch("observed_access")).to include("resource" => "TCP/12345", "operation_label" => "bind")
    end

    it "keeps equivalent normal ingestion current while updating count, coverage and last seen, without intent/history writes" do
      issue, occurrence, = fixture
      intent = select_candidate(issue, boolean: "nis_enabled")
      reviewed = intent.attributes.deep_dup
      history_count = ResolutionIntentChange.where(issue: issue).count
      last_seen = issue.last_seen_at
      get "/api/v1/issues/#{issue.id}"
      expect(JSON.parse(response.body).dig("finding_coverage", "conditional_allow_inactive")).to eq(1)

      new_occurrence = ingest_equivalent(issue, occurrence)
      expect(ResolutionIntent.find(intent.id).attributes).to eq(reviewed)
      expect(ResolutionIntentChange.where(issue: issue).count).to eq(history_count)
      get "/api/v1/issues/#{issue.id}"
      body = JSON.parse(response.body)
      expect(body.dig("issue", "occurrences_count")).to eq(2)
      expect(body.dig("finding_coverage", "conditional_allow_inactive")).to eq(2)
      expect(issue.reload.last_seen_at).to eq(new_occurrence.occurred_at)
      expect(issue.last_seen_at).to be > last_seen
      expect(body.dig("resolutions", "freshness")).to eq("current")
      expect(body.dig("resolutions", "change_plan")).to eq(reviewed.fetch("plan_snapshot"))
      candidate = body.dig("resolutions", "candidates").find { |c| c["id"] == intent.candidate_id }
      expect(candidate["evidence_version"]).to eq(intent.evidence_version)
      expect(candidate).not_to have_key("semantic_plan_basis")
      expect(ResolutionIntent.find(intent.id).attributes).to eq(reviewed)
    end

    it "keeps the selected labeling path current after repeated same-path inspection and growth for another path" do
      issue, occurrence, = fixture(network: false, path: "/var/www/a")
      intent = select_candidate(issue, path: "/var/www/a")
      reviewed = intent.attributes.deep_dup
      ingest_equivalent(issue, occurrence, path: "/var/www/a")
      expect(workflow(issue)["freshness"]).to eq("current")
      ingest_equivalent(issue, occurrence, path: "/var/www/b", expected_context: "system_u:object_r:var_t:s0")
      body = workflow(issue)
      expect(body["candidates"].size).to eq(2)
      expect(body["freshness"]).to eq("current")
      expect(body["change_plan"]).to eq(reviewed.fetch("plan_snapshot"))
      expect(ResolutionIntent.find(intent.id).attributes).to eq(reviewed)
      expect(ResolutionIntentChange.where(issue: issue).count).to eq(1)
    end

    it "requires review when the selected resource's authoritative expected context changes" do
      issue, occurrence, = fixture(network: false, path: "/var/www/a")
      intent = select_candidate(issue, path: "/var/www/a")
      reviewed = intent.attributes.deep_dup
      ingest_equivalent(issue, occurrence, path: "/var/www/a", expected_context: "system_u:object_r:var_t:s0")
      body = workflow(issue)
      expect(body["candidates"].sole["id"]).to eq(intent.candidate_id)
      expect(body["freshness"]).to eq("evidence_changed")
      expect(body["change_plan"]).to be_nil
      expect(ResolutionIntent.find(intent.id).attributes).to eq(reviewed)
      expect(ResolutionIntentChange.where(issue: issue).count).to eq(1)
    end

    it "does not tie a reviewed host-wide mechanism to mixed historical occurrence coverage" do
      issue, occurrence, host, snapshot = fixture
      intent = select_candidate(issue, boolean: "nis_enabled")
      active_snapshot = HostSnapshot.create!(host: host, details: snapshot.details.deep_merge("selinux" => {
        "booleans" => %w[httpd_can_network_connect nis_enabled].map { |name| { "name" => name, "status" => "observed", "current" => true } }
      }))
      raw = occurrence.raw_event.dup
      raw.audit_sequence = 2
      raw.host_snapshot = active_snapshot
      raw.save!
      denial = occurrence.normalized_denial.dup
      denial.raw_event = raw
      denial.save!
      Occurrence.create!(organization: issue.organization, issue: issue, host: host, raw_event: raw,
        host_snapshot: active_snapshot, normalized_denial: denial, occurred_at: raw.audit_timestamp)
      get "/api/v1/issues/#{issue.id}"
      body = JSON.parse(response.body)
      expect(body.dig("finding_coverage", "conditional_allow_inactive")).to eq(1)
      expect(body.dig("finding_coverage", "unexplained")).to eq(1)
      expect(body.dig("resolutions", "freshness")).to eq("current")
      expect(ResolutionIntent.find(intent.id).evidence_version).to eq(intent.evidence_version)
    end

    it "withholds enablement when current boolean evidence becomes On without changing intent history" do
      issue, _, host, snapshot = fixture
      intent = select_candidate(issue, boolean: "nis_enabled")
      reviewed = intent.attributes.deep_dup
      details = snapshot.details.deep_dup
      details["selinux"]["booleans"].find { |b| b["name"] == "nis_enabled" }["current"] = true
      latest = HostSnapshot.create!(host: host, details: details)
      host.host_snapshot_observations.first.update!(host_snapshot: latest)
      body = workflow(issue)
      expect(body["freshness"]).to eq("no_longer_supported")
      expect(body["change_plan"]).to be_nil
      expect(ResolutionIntent.find(intent.id).attributes).to eq(reviewed)
      expect(ResolutionIntentChange.where(issue: issue).count).to eq(1)
    end

    it "requires review across exact current policy identities even when the evaluated rules are identical" do
      issue, _, host, snapshot = fixture
      intent = select_candidate(issue, boolean: "nis_enabled")
      identity = "sha256:#{SecureRandom.hex(32)}"
      fact = PolicyFact.last.dup
      fact.policy_identity = identity
      fact.save!
      latest = HostSnapshot.create!(host: host, details: snapshot.details.deep_merge("selinux" => { "policy_identity" => identity }))
      host.host_snapshot_observations.first.update!(host_snapshot: latest)
      body = workflow(issue)
      expect(body["freshness"]).to eq("evidence_changed")
      expect(body["change_plan"]).to be_nil
      expect(body["candidates"].find { |c| c["id"] == intent.candidate_id }["status"]).to eq("proposed")
    end

    it "withholds a candidate whose matching policy condition disappeared" do
      issue, = fixture
      select_candidate(issue, boolean: "nis_enabled")
      PolicyFact.last.update!(matching_rules: [])
      expect(workflow(issue)).to include("freshness" => "no_longer_supported", "change_plan" => nil)
    end

    it "requires review when the relevant matching path changes while the candidate is still eligible" do
      issue, = fixture
      intent = select_candidate(issue, boolean: "nis_enabled")
      fact = PolicyFact.last
      fact.update!(matching_rules: ["allow httpd_t port_type:tcp_socket name_connect; [ nis_enabled ]:True"])
      body = workflow(issue)
      expect(body["candidates"].sole).to include("id" => intent.candidate_id, "status" => "proposed")
      expect(body).to include("freshness" => "evidence_changed", "change_plan" => nil)
    end

    it "checks current eligibility even when the semantic digest itself is unchanged" do
      issue, _, host, = fixture
      intent = select_candidate(issue, boolean: "nis_enabled")
      host.host_snapshot_observations.first.update!(last_received_at: 1.hour.ago)
      body = workflow(issue)
      candidate = body["candidates"].find { |c| c["id"] == intent.candidate_id }
      expect(candidate["evidence_version"]).to eq(intent.evidence_version)
      expect(candidate["status"]).to eq("evidence_changed")
      expect(body).to include("freshness" => "evidence_changed", "change_plan" => nil)
    end

    it "keeps ordering and unrelated observation metadata out of boolean semantics" do
      issue, _, host, snapshot = fixture
      fact = PolicyFact.last
      rules = ["allow httpd_t port_type:tcp_socket { getattr name_connect }; [ nis_enabled ]:True", fact.matching_rules.last]
      details = rules.map { |rule| { "rule" => rule, "conditional_expression" => "nis_enabled", "conditional_branch" => "True", "permissions" => %w[getattr name_connect] } }
      fact.update!(matching_rules: rules, rule_details: details)
      intent = select_candidate(issue, boolean: "nis_enabled")
      fact.update!(matching_rules: rules.reverse, rule_details: details.reverse.map { |d| d.merge("permissions" => d["permissions"].reverse).to_a.reverse.to_h }, evaluated_at: Time.current)
      latest_details = snapshot.details.deep_dup
      latest_details["selinux"]["booleans"].reverse!
      latest_details["selinux"]["booleans"].each { |b| b["description"] = "Updated display metadata"; b["default"] = true }
      latest = HostSnapshot.create!(host: host, details: latest_details)
      host.host_snapshot_observations.first.update!(host_snapshot: latest)
      body = workflow(issue)
      expect(body["freshness"]).to eq("current")
      expect(body["candidates"].sole["evidence_version"]).to eq(intent.evidence_version)
    end

    it "does not stale an independent conditional path when a sibling path in the same policy fact changes" do
      issue, = fixture
      intent = select_candidate(issue, boolean: "nis_enabled")
      fact = PolicyFact.last
      fact.update!(matching_rules: fact.matching_rules.select { |rule| rule.include?("nis_enabled") })
      body = workflow(issue)
      expect(body["freshness"]).to eq("current")
      expect(body["candidates"].sole["id"]).to eq(intent.candidate_id)
    end

    it "canonicalizes shared file-context configuration but detects a changed resolver inventory" do
      issue, _, host, snapshot = fixture(network: false, path: "/var/www/a")
      contexts = [{ "pattern" => "/", "context" => "u:object_r:root_t:s0", "file_type" => "directory" },
        { "pattern" => "/var/www(/.*)?", "context" => "u:object_r:httpd_sys_content_t:s0", "file_type" => "all files" }]
      snapshot.update!(details: snapshot.details.deep_merge("selinux" => { "policy" => { "file_contexts" => contexts } }))
      select_candidate(issue, path: "/var/www/a")
      latest = HostSnapshot.create!(host: host, details: snapshot.details.deep_merge("selinux" => {
        "policy" => { "file_contexts" => contexts.reverse, "port_inventory" => { "unrelated" => true } }
      }))
      host.host_snapshot_observations.first.update!(host_snapshot: latest)
      expect(workflow(issue)["freshness"]).to eq("current")
      latest.update!(details: latest.details.deep_merge("selinux" => { "policy" => { "file_contexts" => [] } }))
      expect(workflow(issue)).to include("freshness" => "evidence_changed", "change_plan" => nil)
    end

    it "requires review for an explicit plan-semantics version bump even with unchanged external evidence" do
      issue, = fixture
      select_candidate(issue, boolean: "nis_enabled")
      stub_const("ResolutionCandidates::PLAN_SEMANTICS_VERSION", 2)
      body = workflow(issue)
      expect(body).to include("freshness" => "evidence_changed", "change_plan" => nil)
      expect(body["freshness_reasons"].sole).to include("Plan-generation semantics changed")
    end

    it "preserves legacy intent records but requires review instead of silently accepting their old broad digest" do
      issue, = fixture
      intent = select_candidate(issue, boolean: "nis_enabled")
      intent.update_columns(semantic_plan_basis: nil, plan_semantics_version: nil)
      legacy = intent.reload.attributes.deep_dup
      body = workflow(issue)
      expect(body).to include("freshness" => "evidence_changed", "change_plan" => nil)
      expect(body["freshness_reasons"].sole).to include("predates the semantic freshness model")
      expect(ResolutionIntent.find(intent.id).attributes).to eq(legacy)
      expect(ResolutionIntentChange.where(issue: issue).count).to eq(1)
    end

    it "rejects an altered persisted semantic basis even if its digest token was not changed" do
      issue, = fixture
      intent = select_candidate(issue, boolean: "nis_enabled")
      intent.update_column(:semantic_plan_basis, intent.semantic_plan_basis.merge("host_id" => -1))
      expect(workflow(issue)).to include("freshness" => "evidence_changed", "change_plan" => nil)
    end
  end

  it "offers independent exact-rule boolean candidates, hides commands until persisted intent, and restores across login" do
    issue, = fixture
    body = workflow(issue)
    expect(body["candidates"].size).to eq(2)
    expect(body.to_json).not_to include("setsebool")
    expect(body["change_plan"]).to be_nil
    first, second = body["candidates"]
    expect(first).to include("mechanically_supported" => true, "intent_confirmation_required" => true, "status" => "proposed")
    mutate("/api/v1/issues/#{issue.id}/resolution-intent", candidate_id: first["id"], evidence_version: first["evidence_version"])
    expect(response).to have_http_status(:ok)
    sign_out_operator
    sign_in_operator
    selected = workflow(issue)
    expect(selected["freshness"]).to eq("current")
    plan = selected["change_plan"]
    expect(plan["apply_steps"].map { |s| s["command"] }).to eq(["sudo setsebool httpd_can_network_connect on", "sudo setsebool -P httpd_can_network_connect on"])
    expect(plan["rollback_steps"].map { |s| s["command"] }).to eq(["sudo setsebool httpd_can_network_connect off"])
    expect(plan["rollback_description"]).to include("Persistent rollback state unknown")
    mutate("/api/v1/issues/#{issue.id}/resolution-intent", candidate_id: second["id"], evidence_version: second["evidence_version"])
    expect(response).to have_http_status(:ok)
    expect(workflow(issue).dig("change_plan", "apply_steps", 0, "command")).to eq("sudo setsebool nis_enabled on")
    mutate("/api/v1/issues/#{issue.id}/resolution-intent", method: :delete)
    cleared = workflow(issue)
    expect(cleared["change_plan"]).to be_nil
    expect(cleared["intent"]).to be_nil
    expect(cleared["history"].map { |c| c["action"] }).to eq(%w[cleared changed selected])
  end

  it "withholds stale plans and rejects old-version selection when policy evidence changes" do
    issue, = fixture
    first = workflow(issue)["candidates"].first
    mutate("/api/v1/issues/#{issue.id}/resolution-intent", candidate_id: first["id"], evidence_version: first["evidence_version"])
    PolicyFact.last.update!(evaluator_version: "new-evaluator")
    changed = workflow(issue)
    expect(changed["freshness"]).to eq("evidence_changed")
    expect(changed["change_plan"]).to be_nil
    mutate("/api/v1/issues/#{issue.id}/resolution-intent", candidate_id: first["id"], evidence_version: first["evidence_version"])
    expect(response).to have_http_status(:conflict)
    reviewed = workflow(issue)["candidates"].first
    mutate("/api/v1/issues/#{issue.id}/resolution-intent", candidate_id: reviewed["id"], evidence_version: reviewed["evidence_version"])
    expect(workflow(issue)["freshness"]).to eq("current")
  end

  it "recognizes a newer On checkpoint without erasing the older inactive finding" do
    issue, occurrence, host, snapshot = fixture
    first = workflow(issue)["candidates"].first
    mutate("/api/v1/issues/#{issue.id}/resolution-intent", candidate_id: first["id"], evidence_version: first["evidence_version"])
    details = snapshot.details.deep_dup
    details["selinux"]["booleans"][0]["current"] = true
    latest = HostSnapshot.create!(host: host, details: details)
    host.host_snapshot_observations.first.update!(host_snapshot: latest)
    body = workflow(issue)
    expect(body["freshness"]).to eq("no_longer_supported")
    expect(body["change_plan"]).to be_nil
    expect(occurrence.reload.host_snapshot_id).to eq(snapshot.id)
    expect(body["candidates"].last["status"]).to eq("proposed")
    relevant, incidental = body["candidates"]
    expect(relevant).to include("presentation" => "primary", "latest_observed_at" => host.host_snapshot_observations.first.last_observed_at.iso8601(3))
    expect(relevant["unavailable_reason"]).to include("already On", "retry")
    expect(relevant.dig("evidence_basis", "occurrence_id")).to eq(occurrence.id)
    expect(relevant.dig("evidence_basis", "checkpoint_value")).to eq(false)
    expect(relevant.dig("evidence_basis", "current_boolean", "current")).to eq(true)
    expect(incidental).to include("presentation" => "technical_alternative")
    expect(incidental["presentation_reason"]).to include("source attribute")
  end

  it "explains the stale prerequisite for a retained restoration candidate" do
    issue, _, host, = fixture(network: false)
    host.host_snapshot_observations.first.update!(last_received_at: 1.hour.ago)
    candidate = workflow(issue)["candidates"].sole
    expect(candidate).to include("status" => "evidence_changed")
    expect(candidate["unavailable_reason"]).to include("missing or stale")
  end

  it "keeps entrypoint guidance and restoration examples attached to their own host, occurrence and path" do
    issue, first, = fixture(network: false, path: "/var/www/earlier-launch")
    _, later, = fixture(network: false, path: "/srv/other-launch", issue: issue)
    later.update!(issue: issue, occurred_at: first.occurred_at + 1.second)
    get "/api/v1/issues/#{issue.id}"
    body = JSON.parse(response.body)
    expect(body.dig("operator_guidance", "source")).to include("host_id" => later.host_id, "occurrence_id" => later.id, "path" => "/srv/other-launch")
    expect(body.dig("operator_guidance", "possible_fix")).to include("does not establish that restoration will permit execution")
    expect(body["resolutions"]["candidates"].map { |c| [c["host_id"], c.dig("evidence_basis", "occurrence_id"), c.dig("evidence_basis", "path")] }).to contain_exactly(
      [first.host_id, first.id, "/var/www/earlier-launch"], [later.host_id, later.id, "/srv/other-launch"])
    expect(body["triage_guidance"]).to be_nil
    expect(issue.reload.occurrences.count).to eq(2)
  end

  it "generates a single-object labeling plan with shell-safe arguments and no invented rollback" do
    issue, = fixture(network: false)
    body = workflow(issue)
    candidate = body["candidates"].sole
    expect(candidate["kind"]).to eq("restore_configured_label")
    mutate("/api/v1/issues/#{issue.id}/resolution-intent", candidate_id: candidate["id"], evidence_version: candidate["evidence_version"])
    plan = workflow(issue)["change_plan"]
    command = plan["apply_steps"].sole["command"]
    expect(Shellwords.split(command)).to eq(["sudo", "restorecon", "-v", "--", "/var/www/html/test file;$(id)"])
    expect(command).not_to include("-R", "chcon", "semanage fcontext")
    expect(plan["rollback_steps"]).to be_empty
    expect(plan["expected_effect"]).to include("does not prove")
  end

  it "retains historical signature intent without selecting it as the relationship's active plan" do
    issue, = fixture(network: false)
    intent = select_candidate(issue)
    signature = issue.signatures.create!(fingerprint_version: 3, fingerprint_digest: "historical", permissions: ["entrypoint"],
      first_seen_at: issue.first_seen_at, last_seen_at: issue.last_seen_at)
    snapshot = intent.plan_snapshot
    intent.update!(issue_signature_id: signature.id)
    ResolutionIntentChange.where(issue: issue).update_all(issue_signature_id: signature.id)
    body = workflow(issue)
    expect(body).to include("intent" => nil, "change_plan" => nil)
    expect(body["history"].sole).to include("issue_signature_id" => signature.id)
    expect(intent.reload.plan_snapshot).to eq(snapshot)
    select_candidate(issue)
    expect(ResolutionIntent.where(issue: issue).count).to eq(2)
  end

  it "keeps remediation evidence permission-specific even for the same host and path" do
    issue, first, = fixture(network: false)
    denial = first.normalized_denial.dup
    denial.assign_attributes(ordinal: 1, permissions: ["read"])
    denial.save!
    second = first.dup
    second.assign_attributes(normalized_denial: denial, occurred_at: first.occurred_at + 1.second)
    second.save!
    issue.update!(permissions: %w[entrypoint read])
    candidates = workflow(issue).fetch("candidates")
    expect(candidates.size).to eq(2)
    expect(candidates.map { |candidate| candidate["id"] }.uniq.size).to eq(2)
    expect(candidates.map { |candidate| candidate["permissions"] }).to contain_exactly(["entrypoint"], ["read"])
    expect(candidates.map { |candidate| candidate.dig("evidence_basis", "permissions") }).to contain_exactly(["entrypoint"], ["read"])
  end

  it "rejects basename-only labeling and complex boolean expressions" do
    issue, occurrence, = fixture(network: false)
    occurrence.normalized_denial.update!(details: { "target_evidence" => { "object_names" => ["file"], "filesystem_paths" => [] } })
    expect(workflow(issue)["candidates"]).to be_empty
    network, = fixture
    PolicyFact.last.update!(matching_rules: ["allow httpd_t port_type:tcp_socket name_connect; [ httpd_can_network_connect && nis_enabled ]:True"])
    body = workflow(network)
    expect(body["candidates"]).to be_empty
    expect(body["rejected_candidates"].to_json).to include("Complex")
  end

  it "invalidates a labeling plan when a newer expected-context observation removes support" do
    issue, occurrence, = fixture(network: false)
    candidate = workflow(issue)["candidates"].sole
    mutate("/api/v1/issues/#{issue.id}/resolution-intent", candidate_id: candidate["id"], evidence_version: candidate["evidence_version"])
    observations = occurrence.raw_event.file_context_observations.deep_dup
    observations[0]["expected_context"] = occurrence.normalized_denial.target_context
    observations[0]["observed_at"] = 1.second.from_now.iso8601(6)
    occurrence.raw_event.update!(file_context_observations: observations)
    body = workflow(issue)
    expect(body["freshness"]).to eq("no_longer_supported")
    expect(body["change_plan"]).to be_nil
    expect(body["freshness_reasons"].sole).to include("configured-label mismatch", "expected-context observations")
  end

  it "requests new current-policy questions asynchronously and never invokes policy tooling in the request" do
    issue, _, host, snapshot = fixture
    current_identity = "sha256:#{SecureRandom.hex(32)}"
    latest = HostSnapshot.create!(host: host, details: snapshot.details.deep_merge("selinux" => { "policy_identity" => current_identity }))
    host.host_snapshot_observations.first.update!(host_snapshot: latest)
    expect(Open3).not_to receive(:capture3)
    expect(RequestResolutionPolicyFactsJob).to receive(:perform_later).with(issue_id: issue.id).once
    expect(workflow(issue)["candidates"].map { |c| c["status"] }).to eq(%w[no_longer_supported no_longer_supported])
    RequestResolutionPolicyFactsJob.perform_now(issue_id: issue.id)
    expect(PolicyFact.find_by!(policy_identity: current_identity)).to have_attributes(status: "pending", permission: "name_connect")
  end

  it "stages durable deduplicated permissions from multiple occurrences and rejects cross-organization sources" do
    issue, occurrence, = fixture
    workflow(issue)
    mutate("/api/v1/policy-drafts", method: :post, issue_id: issue.id, name: "Web review")
    expect(response).to have_http_status(:created)
    id = JSON.parse(response.body)["id"]
    2.times { mutate("/api/v1/policy-drafts/#{id}/entries", method: :post, issue_id: issue.id, occurrence_id: occurrence.id) }
    expect(response).to have_http_status(:ok)
    expect(JSON.parse(response.body)["entries"].sole["provenance"].size).to eq(1)
    other = issue
    another = occurrence.dup
    another.issue = other
    denial = occurrence.normalized_denial.dup
    denial.ordinal = 1
    denial.save!
    another.normalized_denial = denial
    another.save!
    mutate("/api/v1/policy-drafts/#{id}/entries", method: :post, issue_id: other.id, occurrence_id: another.id)
    expect(response).to have_http_status(:ok)
    draft = JSON.parse(response.body)
    expect(draft["entries"].size).to eq(1)
    expect(draft["entries"].sole["provenance"].size).to eq(2)
    expect(draft["entries"].sole["provenance"].first["known_alternatives"].size).to eq(2)
    foreign, foreign_occurrence, = fixture(organization: Organization.create!(name: "foreign"))
    mutate("/api/v1/policy-drafts/#{id}/entries", method: :post, issue_id: foreign.id, occurrence_id: foreign_occurrence.id)
    expect(response).to have_http_status(:not_found)
    get "/api/v1/policy-drafts", params: { issue_id: issue.id }
    expect(JSON.parse(response.body)["drafts"].sole["entries"].size).to eq(1)
    mutate("/api/v1/policy-drafts/#{id}/export", method: :post, format: "te", module_name: "local_web")
    expect(response).to have_http_status(:unprocessable_content)
    mutate("/api/v1/policy-drafts/#{id}/export", method: :post, format: "te", module_name: "x;id", literal_confirmed: true, evidence_version: draft["evidence_version"])
    expect(response).to have_http_status(:unprocessable_content)
    mutate("/api/v1/policy-drafts/#{id}/export", method: :post, format: "te", module_name: "local_web", literal_confirmed: true, evidence_version: "stale")
    expect(response).to have_http_status(:unprocessable_content)
    mutate("/api/v1/policy-drafts/#{id}/export", method: :post, format: "te", module_name: "local_web", literal_confirmed: true, evidence_version: draft["evidence_version"])
    expect(response).to have_http_status(:ok)
    exported = JSON.parse(response.body)
    expect(exported["validation_status"]).to eq("unvalidated")
    expect(exported["content"]).to include("allow httpd_t unreserved_port_t:tcp_socket name_connect;")
    expect(exported["build_steps"].join).not_to include("semodule -i")
  end

  it "requires authentication and CSRF for intent mutations" do
    issue, = fixture
    candidate = workflow(issue)["candidates"].first
    original = Api::V1::BaseController.config.allow_forgery_protection
    begin
      Api::V1::BaseController.config.allow_forgery_protection = true
      patch "/api/v1/issues/#{issue.id}/resolution-intent", params: { candidate_id: candidate["id"], evidence_version: candidate["evidence_version"] }.to_json, headers: { "Content-Type" => "application/json" }
      expect(response).to have_http_status(:unprocessable_content)
    ensure
      Api::V1::BaseController.config.allow_forgery_protection = original
    end
    sign_out_operator
    get "/api/v1/issues/#{issue.id}/resolutions"
    expect(response).to have_http_status(:unauthorized)
  end
end
