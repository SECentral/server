require "rails_helper"

RSpec.describe "Events API", type: :request do
  before do
    cleanup_database
    organization
  end

  after do
    cleanup_database
  end

  def cleanup_database
    Occurrence.delete_all
    NormalizedDenial.delete_all
    PolicyFact.delete_all
    PolicyArtifact.delete_all
    IssueDispositionChange.delete_all
    Issue.delete_all
    RawAuditRecord.delete_all
    RawEvent.delete_all
    HostSnapshotObservation.delete_all
    HostSnapshot.delete_all
    AgentInstallation.delete_all
    Host.delete_all
    Organization.delete_all
  end

  let(:organization) { Organization.create!(name: "Test organization") }
  let(:headers) { { "CONTENT_TYPE" => "application/json", "Authorization" => "Bearer test-ingestion-key" } }

  def ingestion_state
    models = [Host, AgentInstallation, HostSnapshot, HostSnapshotObservation, RawEvent,
      RawAuditRecord, NormalizedDenial, Occurrence, Issue, PolicyFact, PolicyArtifact]
    models.to_h { |model| [model.name, model.order(:id).map(&:attributes)] }.merge(
      "effective_trust" => Host.order(:id).map { |host| [host.id, host.selinux_state_for] })
  end

  def seed_validation_state
    checkpoint = boolean_checkpoint(1)
    bytes = "pre-persistence validation fixture"
    identity = "sha256:#{Digest::SHA256.hexdigest(bytes)}"
    checkpoint["host"]["selinux"]["policy_identity"] = identity
    post "/api/v1/heartbeat", params: checkpoint.to_json, headers: headers
    post "/api/v1/events", params: ingest_request(sequence: 8000, raw_payload: avc_payload("/srv/seed", ["read"])).to_json, headers: headers
    expect(response).to have_http_status(:accepted)
    PolicyArtifactIngestion.call(host: Host.sole, policy_identity: identity, bytes: bytes)
    PolicyFactRequest.for_event(RawEvent.sole)
  end

  def with_exception_rendering
    environment = Rails.application.env_config
    saved = environment.slice("action_dispatch.show_exceptions", "action_dispatch.show_detailed_exceptions")
    environment["action_dispatch.show_exceptions"] = :all
    environment["action_dispatch.show_detailed_exceptions"] = false
    yield
  ensure
    environment.merge!(saved)
  end

  shared_examples "indexed pre-persistence validation" do
    it "rejects deterministically without entering persistence, locking a host or changing state" do
      seed_validation_state
      before = ingestion_state
      expect_any_instance_of(IngestEvents).not_to receive(:persist_raw_envelope!)
      expect(Host).not_to receive(:find_for_ingestion!)
      expect_any_instance_of(Host).not_to receive(:with_lock)
      2.times do
        expect {
          post "/api/v1/events", params: malformed_request.to_json, headers: headers
        }.not_to have_enqueued_job
        expect(response).to have_http_status(:unprocessable_content)
        expect(response.parsed_body.fetch("error")).to include("code" => "invalid_request", "phase" => "pre_persistence")
        details = response.parsed_body.dig("error", "details")
        expect(details).to include(*expected_details)
        expect(details).to all(include("path" => /\Aevents\[\d+\](?:\.|\z)/, "code" => /\A[a-z][a-z0-9_]*\z/))
        @first_validation_details ||= details
        expect(details).to eq(@first_validation_details)
        expect(ingestion_state).to eq(before)
      end
    end
  end

  shared_examples "no pre-persistence guarantee" do
    it "does not claim pre-persistence even when final rows might be unchanged" do
      seed_validation_state
      entries = 0
      allow_any_instance_of(IngestEvents).to receive(:persist_raw_envelope!).and_wrap_original do |original, *args|
        entries += 1
        original.call(*args)
      end
      submit_failure.call
      expect(response.status).to eq(expected_status)
      error = response.parsed_body["error"]
      expect(error).not_to have_key("phase") if error.is_a?(Hash)
      expect(entries).to eq(expected_entries)
    end
  end

  it "accepts and deduplicates an authenticated batch" do
    request = ingest_request

    post "/api/v1/events", params: request.to_json, headers: headers
    expect(response).to have_http_status(:accepted)
    post "/api/v1/events", params: request.to_json, headers: headers
    expect(response).to have_http_status(:accepted)

    expect(RawEvent.count).to eq(1)
    expect(RawEvent.first).to have_attributes(category: "avc", transition_type: nil)
    expect(RawAuditRecord.count).to eq(1)
    expect(HostSnapshot.count).to eq(0)
    expect(RawEvent.first.host_snapshot).to be_nil
    expect(RawAuditRecord.first.payload).to eq("avc: denied")
    expect(RawEvent.first).to have_attributes(
      host_observed_at: Time.iso8601(request.fetch("host_observed_at")),
      agent_received_at: Time.iso8601(request.dig("events", 0, "agent_received_at"))
    )
    expect(RawEvent.first.server_received_at).to be_present
    expect(HostSnapshotObservation.count).to eq(0)
  end

  it "accepts the collector's textual SELINUX_ERR identity without changing denial semantics" do
    request = selinux_error_request
    post "/api/v1/events", params: request.to_json, headers: headers
    expect(response).to have_http_status(:accepted)
    event = RawEvent.sole
    expect(event).to have_attributes(category: "avc", transition_type: nil, checkpoint_invalidated_fields: [])
    expect(event.raw_audit_records.order(:position).pluck(:record_type)).to eq([1400, 1401, 1300, 1327, 1320])
    expect(event.raw_audit_records.order(:position).pluck(:payload)).to eq(request["events"][0]["records"].map { |r| Base64.strict_decode64(r["payload"]) })
    expect(Occurrence.count).to eq(1)
  end

  it "deduplicates numeric and case aliases with identical evidence and rejects changed payloads" do
    request = selinux_error_request
    digests = []
    [1401, "SELINUX_ERR", "selinux_err"].product(%w[SELINUX_ERR selinux_err]).each do |type, name|
      request["events"][0]["records"][1].merge!("type" => type, "type_name" => name)
      digests << EvidenceDigest.call(request["events"][0])
      post "/api/v1/events", params: request.to_json, headers: headers
      expect(response).to have_http_status(:accepted)
    end
    expect(digests.uniq.size).to eq(1)
    expect(RawEvent.sole.evidence_digest).to eq(digests.first)
    expect(Occurrence.count).to eq(1)
    request["events"][0]["records"][1]["payload"] = Base64.strict_encode64("different evidence")
    post "/api/v1/events", params: request.to_json, headers: headers
    expect(response).to have_http_status(:unprocessable_content)
    expect(JSON.parse(response.body).dig("error", "details")).to include("path" => "events", "code" => "conflicting_duplicate")
    expect(RawEvent.count).to eq(1)
  end

  it "requires primary AVC evidence before accepting its optional observation in a SELINUX_ERR batch" do
    request = ingest_request(raw_payload: avc_payload("/srv/test", ["read"]))
    request["events"] << selinux_error_request["events"][0].tap do |event|
      event["audit_event"]["sequence"] = 8125
      event["records"].each { |record| record["sequence"] = 8125 }
    end
    observation = expected_context_request(request, path: "/srv/test")
    post "/api/v1/expected-context-observations", params: observation.to_json, headers: headers
    expect(response).to have_http_status(:not_found)
    expect(RawEvent.count).to eq(0)
    post "/api/v1/events", params: request.to_json, headers: headers
    expect(response).to have_http_status(:accepted)
    post "/api/v1/expected-context-observations", params: observation.to_json, headers: headers
    expect(response).to have_http_status(:accepted)
    expect(RawEvent.find_by!(audit_sequence: 8124).file_context_observations.size).to eq(1)
    expect(RawEvent.find_by!(audit_sequence: 8125).file_context_observations).to be_empty
  end

  [[1401, "AVC"], [65500, "SELINUX_ERR"], [1401, "invented_type"],
   ["invented_type", "SELINUX_ERR"], [1401, nil], [nil, "SELINUX_ERR"]].each do |type, name|
    it "rejects incompatible or missing SELINUX_ERR metadata #{[type, name].inspect} atomically" do
      request = selinux_error_request
      request["events"][0]["records"][1].merge!("type" => type, "type_name" => name)
      request["events"] << ingest_request(sequence: 8125)["events"][0]
      post "/api/v1/events", params: request.to_json, headers: headers
      expect(response).to have_http_status(:unprocessable_content)
      expect(RawEvent.count).to eq(0)
      expect(Occurrence.count).to eq(0)
      expect(JSON.parse(response.body).dig("error", "details")).to include(
        hash_including("path" => /events\[0\].records\[1\].type/))
    end
  end

  it "preserves existing opaque numeric/UNKNOWN type acceptance and arbitrary-text rejection" do
    [[65500, "UNKNOWN[65500]"], ["unknown[65500]", "UNKNOWN[65500]"], [65500, "opaque_diagnostic"]].each_with_index do |(type, name), index|
      request = selinux_error_request
      request["events"][0]["records"][1].merge!("type" => type, "type_name" => name)
      request["events"][0]["audit_event"]["sequence"] += index
      request["events"][0]["records"].each { |r| r["sequence"] += index }
      post "/api/v1/events", params: request.to_json, headers: headers
      expect(response).to have_http_status(:accepted)
      expect(RawEvent.last.raw_audit_records.find_by!(position: 1).record_type).to eq(65500)
      expect(RawEvent.last.transition_type).to be_nil
    end
    request = selinux_error_request
    request["events"][0]["records"][1].merge!("type" => "invented_type", "type_name" => "invented_type")
    post "/api/v1/events", params: request.to_json, headers: headers
    expect(response).to have_http_status(:unprocessable_content)
    expect(RawEvent.count).to eq(3)
  end

  it "resolves every registered type in numeric, upper-case and lower-case form" do
    [["AVC", 1400], ["SELINUX_ERR", 1401], ["USER_AVC", 1107], ["SYSCALL", 1300],
     ["PATH", 1302], ["AVC_PATH", 1402], ["PROCTITLE", 1327], ["EXECVE", 1309],
     ["CWD", 1307], ["EOE", 1320], ["MAC_POLICY_LOAD", 1403], ["MAC_CONFIG_CHANGE", 1405],
     ["MAC_STATUS", 1404], ["USER_MAC_CONFIG_CHANGE", 2312]].each_with_index do |(name, code), index|
      [code, name, name.downcase].each do |type|
        expect(IngestEvents.type_code(type)).to eq(code)
        request = ingest_request(sequence: 8200 + index)
        record = request["events"][0]["records"][0].merge("position" => 1, "type" => type, "type_name" => name)
        request["events"][0]["records"] << record
        post "/api/v1/events", params: request.to_json, headers: headers
        expect(response).to have_http_status(:accepted)
        expect(RawEvent.find_by!(audit_sequence: 8200 + index).raw_audit_records.find_by!(position: 1).record_type).to eq(code)
      end
    end
  end

  it "stores an asynchronous expected-context result separately from immutable raw audit evidence" do
    request = ingest_request(raw_payload: avc_payload("/srv/test", ["read"]))
    request["host_observed_at"] = "2026-09-13T17:29:00.000000123Z"
    post "/api/v1/events", params: request.to_json, headers: headers
    raw_event = RawEvent.sole
    digest = raw_event.evidence_digest
    raw_records = raw_event.raw_audit_records.pluck(:payload)

    observation = expected_context_request(request, path: "/srv/test")
    post "/api/v1/expected-context-observations", params: observation.to_json, headers: headers
    expect(response).to have_http_status(:accepted)
    expect(raw_event.reload.file_context_observations).to eq([{
      "path" => "/srv/test", "object_class" => "file", "file_type" => "file",
      "expected_context" => "system_u:object_r:httpd_sys_content_t:s0",
      "observed_at" => "2026-09-13T17:30:13.000000Z", "resolver" => "matchpathcon",
      "status" => "resolved", "kind" => "expected_context", "host_observed_at" => "2026-09-13T17:29:00.000000123Z"
    }])
    expect(raw_event.evidence_digest).to eq(digest)
    expect(raw_event.raw_audit_records.pluck(:payload)).to eq(raw_records)

    post "/api/v1/expected-context-observations", params: observation.to_json, headers: headers
    expect(response).to have_http_status(:accepted)
    expect(raw_event.reload.file_context_observations.size).to eq(1)

    conflicting = observation.deep_dup
    conflicting.dig("observation")["expected_context"] = "system_u:object_r:other_t:s0"
    post "/api/v1/expected-context-observations", params: conflicting.to_json, headers: headers
    expect(response).to have_http_status(:conflict)
    expect(raw_event.reload.file_context_observations.size).to eq(1)
  end

  it "rejects an expected-context path that is not present in retained audit evidence" do
    request = ingest_request(raw_payload: 'avc: denied { read } for name="basename" scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:user_home_t:s0 tclass=file')
    post "/api/v1/events", params: request.to_json, headers: headers
    raw_event = RawEvent.sole
    expect(raw_event.normalized_denials.first.details.dig("target_evidence", "filesystem_paths")).to be_empty

    observation = expected_context_request(request, path: "/var/www/html/basename")
    post "/api/v1/expected-context-observations", params: observation.to_json, headers: headers
    expect(response).to have_http_status(:unprocessable_content)
    expect(raw_event.reload.file_context_observations).to be_empty
  end

  it "retains unavailable and error expected-context results without a guessed label" do
    [ ["unavailable", "resolver_unavailable"], ["error", "resolver_timeout"] ].each_with_index do |(status, reason), index|
      request = ingest_request(sequence: 8125 + index, raw_payload: avc_payload("/srv/#{index}", ["read"]))
      post "/api/v1/events", params: request.to_json, headers: headers
      observation = expected_context_request(request, path: "/srv/#{index}", status: status, reason: reason)
      observation.dig("observation").delete("file_type")
      observation.dig("observation").delete("expected_context")
      post "/api/v1/expected-context-observations", params: observation.to_json, headers: headers
      expect(response).to have_http_status(:accepted)
      expect(RawEvent.order(:id).last.file_context_observations.last).to include("status" => status, "reason" => reason)
      expect(RawEvent.order(:id).last.file_context_observations.last).not_to have_key("expected_context")
    end
  end

  it "associates events with a matching heartbeat checkpoint without changing current state" do
    checkpoint = heartbeat_request
    checkpoint["host"]["selinux"]["policy_identity"] = "sha256:" + "a" * 64
    post "/api/v1/heartbeat", params: checkpoint.to_json, headers: headers
    observed_snapshot = HostSnapshot.last

    event = ingest_request
    post "/api/v1/events", params: event.to_json, headers: headers

    expect(RawEvent.last.host_snapshot).to eq(observed_snapshot)
    expect(RawEvent.last.host_snapshot.details.dig("selinux", "policy_identity")).to eq(checkpoint.dig("host", "selinux", "policy_identity"))
    expect(RawEvent.last.occurrences.first.host_snapshot).to eq(observed_snapshot)
    expect(HostSnapshotObservation.count).to eq(1)
  end

  it "does not associate a checkpoint from another boot" do
    post "/api/v1/heartbeat", params: heartbeat_request.to_json, headers: headers
    event = ingest_request
    event["boot_id"] = "previous-boot"
    post "/api/v1/events", params: event.to_json, headers: headers

    expect(response).to have_http_status(:accepted)
    expect(RawEvent.last.host_snapshot).to be_nil
    expect(RawEvent.last.boot_id).to eq("previous-boot")
  end

  it "does not create or advance host state from event traffic" do
    post "/api/v1/events", params: ingest_request.to_json, headers: headers

    expect(installation.reload.bound_host.current_state_observation).to be_nil
    expect(installation.bound_host.current_snapshot).to be_nil
    expect(RawEvent.last.host_snapshot).to be_nil
  end

  it "accepts events before the first host-state checkpoint" do
    event = ingest_request
    event.delete("host_observed_at")
    post "/api/v1/events", params: event.to_json, headers: headers

    expect(response).to have_http_status(:accepted)
    expect(RawEvent.last.host_observed_at).to be_nil
    expect(RawEvent.last.host_snapshot).to be_nil
    expect(RawAuditRecord.last.payload).to eq("avc: denied")
  end

  it "retains successful policy loads as administrative transitions and blocks stale policy association" do
    checkpoint = heartbeat_request
    old_policy = "old policy bytes"
    old_identity = "sha256:#{Digest::SHA256.hexdigest(old_policy)}"
    checkpoint["host"]["selinux"]["policy_identity"] = old_identity
    post "/api/v1/heartbeat", params: checkpoint.to_json, headers: headers
    old_snapshot = HostSnapshot.last

    post "/api/v1/events", params: policy_load_request.to_json, headers: headers

    transition = RawEvent.sole
    expect(response).to have_http_status(:accepted)
    expect(transition).to have_attributes(category: "selinux_administrative", transition_type: "policy_load", host_snapshot: old_snapshot)
    expect(transition.raw_audit_records.pluck(:record_type, :type_name)).to eq([[ 1403, "MAC_POLICY_LOAD" ], [ 1300, "SYSCALL" ], [ 1327, "PROCTITLE" ]])
    expect(transition.raw_audit_records.first.payload).to include("res=1")
    expect(Occurrence.count).to eq(0)
    expect(Issue.count).to eq(0)
    expect(PolicyFact.count).to eq(0)
    expect(Host.find(transition.host_id).current_policy_identity).to be_nil
    expect(HostSerializer.call(Host.find(transition.host_id), include_snapshot: true).dig(:selinux, :policy_identity)).to be_nil

    put "/api/v1/policy-artifacts/#{old_identity}", params: old_policy,
      headers: { "CONTENT_TYPE" => "application/octet-stream", "Authorization" => "Bearer test-ingestion-key", "X-SECentral-Host-ID" => "host-1" }
    expect(response).to have_http_status(:conflict)
    expect(PolicyArtifact.count).to eq(0)

    stale_heartbeat = checkpoint.deep_dup
    stale_heartbeat["host"]["hostname"] = "stale-pre-load-work"
    post "/api/v1/heartbeat", params: stale_heartbeat.to_json, headers: headers
    expect(HostSnapshot.count).to eq(1)
    expect(HostSnapshot.last).to eq(old_snapshot)

    perform_enqueued_jobs do
      post "/api/v1/events", params: ingest_request(sequence: 8126, raw_payload: avc_payload("/srv/after-load", ["getattr"])).to_json, headers: headers
    end
    expect(RawEvent.last.host_snapshot).to be_nil
    expect(Occurrence.last).to be_present
    expect(PolicyFact.count).to eq(0)

    refreshed = heartbeat_request
    refreshed["host_observed_at"] = "2026-09-13T17:31:00.000000Z"
    refreshed["host"]["selinux"]["policy_identity"] = "sha256:" + "b" * 64
    post "/api/v1/heartbeat", params: refreshed.to_json, headers: headers
    after_refresh = ingest_request(sequence: 8127, raw_payload: avc_payload("/srv/after-refresh", ["getattr"]))
    after_refresh["events"][0]["audit_event"]["timestamp"] = "2026-09-13T17:32:00.000000Z"
    after_refresh["events"][0]["records"][0]["timestamp"] = after_refresh.dig("events", 0, "audit_event", "timestamp")
    after_refresh.merge!("host_observed_at" => refreshed["host_observed_at"])
    perform_enqueued_jobs do
      post "/api/v1/events", params: after_refresh.to_json, headers: headers
    end

    expect(RawEvent.last.host_snapshot).to eq(HostSnapshot.last)
    expect(RawEvent.last.host_snapshot.details.dig("selinux", "policy_identity")).to eq(refreshed.dig("host", "selinux", "policy_identity"))
    expect(PolicyFact.pluck(:policy_identity).uniq).to eq([ refreshed.dig("host", "selinux", "policy_identity") ])
    expect(Host.find(transition.host_id).current_policy_identity).to eq(refreshed.dig("host", "selinux", "policy_identity"))
  end

  it "retains an unsuccessful policy-load report without establishing a transition" do
    checkpoint = heartbeat_request
    post "/api/v1/heartbeat", params: checkpoint.to_json, headers: headers

    post "/api/v1/events", params: policy_load_request(success: false).to_json, headers: headers

    expect(RawEvent.last).to have_attributes(category: "selinux_administrative", transition_type: nil)
    expect(RawAuditRecord.first.payload).to include("res=0")
    expect(Occurrence.count).to eq(0)
  end

  [ [1, 0], [0, 1] ].each do |old_value, new_value|
    it "invalidates boolean #{old_value} -> #{new_value} until refresh, without stale conditional evaluation" do
      checkpoint = boolean_checkpoint(old_value)
      post "/api/v1/heartbeat", params: checkpoint.to_json, headers: headers
      old_snapshot = HostSnapshot.last
      post "/api/v1/events", params: boolean_change_request(old_value: old_value, new_value: new_value).to_json, headers: headers
      transition = RawEvent.last
      expect(response).to have_http_status(:accepted)
      expect(transition).to have_attributes(category: "selinux_administrative", transition_type: "boolean_change")
      expect(transition.boolean_changes).to eq([{ "name" => "httpd_can_network_connect", "old_value" => old_value,
        "new_value" => new_value, "success" => true, "success_source" => "kernel_boolean_commit" }])
      expect([Occurrence.count, Issue.count, PolicyFact.count]).to eq([0, 0, 0])
      expect(transition.host.current_policy_identity).to be_nil
      post "/api/v1/heartbeat", params: checkpoint.to_json, headers: headers
      expect(HostSnapshot.count).to eq(1)

      request = ingest_request(sequence: 8126, raw_payload: connect_payload)
      request["events"][0]["audit_event"]["timestamp"] = "2026-09-13T17:30:13.000000Z"
      request["events"][0]["records"][0]["timestamp"] = request.dig("events", 0, "audit_event", "timestamp")
      post "/api/v1/events", params: request.to_json, headers: headers
      window = Occurrence.last
      expect(window.host_snapshot).to be_nil
      expect(window.raw_event.raw_audit_records.first.payload).to eq(connect_payload)
      PolicyFact.create!(policy_identity: checkpoint.dig("host", "selinux", "policy_identity"), query_kind: "allow",
        source_type: "httpd_t", target_type: "unreserved_port_t", object_class: "tcp_socket", permission: "name_connect",
        status: "matched", matching_rules: ["allow httpd_t port_type:tcp_socket name_connect; [ httpd_can_network_connect ]:True"])
      result = PolicyEvaluation.call(window.issue)[:occurrence_evaluations].first
      expect(result).to include(status: "unavailable", rule_state: "unknown", policy_identity: [], booleans: [])
      expect(PolicyFact.count).to eq(1)

      refreshed = boolean_checkpoint(new_value)
      refreshed["host_observed_at"] = "2026-09-13T17:31:00.000000Z"
      post "/api/v1/heartbeat", params: refreshed.to_json, headers: headers
      request = ingest_request(sequence: 8127, raw_payload: connect_payload)
      request["host_observed_at"] = refreshed["host_observed_at"]
      request["events"][0]["audit_event"]["timestamp"] = "2026-09-13T17:32:00.000000Z"
      request["events"][0]["records"][0]["timestamp"] = request.dig("events", 0, "audit_event", "timestamp")
      post "/api/v1/events", params: request.to_json, headers: headers
      expect(Occurrence.last.host_snapshot).to eq(HostSnapshot.last)
      expect(Occurrence.last.host_snapshot).not_to eq(old_snapshot)
      expect(window.reload.host_snapshot).to be_nil
      expect(transition.host.reload.current_policy_identity).to eq(refreshed.dig("host", "selinux", "policy_identity"))
      PolicyFact.create!(policy_identity: refreshed.dig("host", "selinux", "policy_identity"), query_kind: "allow",
        source_type: "httpd_t", target_type: "unreserved_port_t", object_class: "tcp_socket", permission: "name_connect",
        status: "matched", matching_rules: ["allow httpd_t port_type:tcp_socket name_connect; [ httpd_can_network_connect ]:True"])
      results = PolicyEvaluation.call(window.issue)[:occurrence_evaluations].index_by { |item| item[:occurrence_id] }
      expect(results[window.id]).to include(status: "unavailable", rule_state: "unknown")
      expect(results[Occurrence.last.id][:rule_state]).to eq(new_value == 1 ? "conditional_active" : "conditional_inactive")
    end
  end

  it "retains failed boolean history without invalidation and deduplicates retries" do
    checkpoint = boolean_checkpoint(1)
    post "/api/v1/heartbeat", params: checkpoint.to_json, headers: headers
    request = boolean_change_request(result: "0")
    2.times { post "/api/v1/events", params: request.to_json, headers: headers }
    expect(RawEvent.count).to eq(1)
    expect(RawEvent.last.transition_type).to be_nil
    expect(RawEvent.last.boolean_changes.first["success"]).to be(false)
    expect(RawEvent.last.host.current_policy_identity).to eq(checkpoint.dig("host", "selinux", "policy_identity"))
    post "/api/v1/events", params: ingest_request(sequence: 8126, raw_payload: connect_payload).to_json, headers: headers
    expect(Occurrence.last.host_snapshot).to eq(HostSnapshot.last)
  end

  it "retracts stale associations on delayed transition delivery, using serial order at timestamp ties" do
    post "/api/v1/heartbeat", params: boolean_checkpoint(1).to_json, headers: headers
    # All share a timestamp: 8123 precedes the boundary, 8126 follows it.
    post "/api/v1/events", params: ingest_request(sequence: 8123, raw_payload: connect_payload).to_json, headers: headers
    before = Occurrence.last
    post "/api/v1/events", params: ingest_request(sequence: 8126, raw_payload: connect_payload).to_json, headers: headers
    after = Occurrence.last
    expect(after.host_snapshot).to be_present
    request = boolean_change_request
    2.times { post "/api/v1/events", params: request.to_json, headers: headers }
    expect(RawEvent.where(transition_type: "boolean_change").count).to eq(1)
    expect(before.reload.host_snapshot).to be_present
    expect(after.reload.host_snapshot).to be_nil
    expect(after.raw_event.reload.host_snapshot).to be_nil
    # Reprocessing a stale in-memory event cannot restore its old association.
    ProcessRawEvent.call(after.raw_event)
    expect(after.reload.host_snapshot).to be_nil
    post "/api/v1/events", params: ingest_request(sequence: 8127, raw_payload: connect_payload).to_json, headers: headers
    expect(Occurrence.last.host_snapshot).to be_nil
  end

  it "keeps snapshot-observed changes distinct from observed transitions" do
    post "/api/v1/heartbeat", params: boolean_checkpoint(1).to_json, headers: headers
    changed = boolean_checkpoint(0)
    changed["host_observed_at"] = "2026-09-13T17:31:00.000000Z"
    post "/api/v1/heartbeat", params: changed.to_json, headers: headers
    expect(HostSnapshot.count).to eq(2)
    expect(RawEvent.count).to eq(0)
  end

  it "requires a checkpoint strictly after the boundary and strictly before the AVC" do
    request = boolean_change_request
    boundary = request.dig("events", 0, "audit_event", "timestamp")
    post "/api/v1/events", params: request.to_json, headers: headers
    checkpoint = boolean_checkpoint(0)
    checkpoint["host_observed_at"] = boundary
    post "/api/v1/heartbeat", params: checkpoint.to_json, headers: headers
    expect(HostSnapshot.count).to eq(0)
    checkpoint["host_observed_at"] = "2026-09-13T17:31:00.000000Z"
    post "/api/v1/heartbeat", params: checkpoint.to_json, headers: headers
    avc = ingest_request(sequence: 8126, raw_payload: connect_payload)
    avc["host_observed_at"] = checkpoint["host_observed_at"]
    avc["events"][0]["audit_event"]["timestamp"] = checkpoint["host_observed_at"]
    avc["events"][0]["records"][0]["timestamp"] = checkpoint["host_observed_at"]
    post "/api/v1/events", params: avc.to_json, headers: headers
    expect(Occurrence.last.host_snapshot).to be_nil
  end

  it "retains multiple authoritative boolean records as one transition and rejects unrelated config records" do
    request = boolean_change_request
    record = request["events"][0]["records"][0].deep_dup
    record["position"] = 3
    record["payload"] = Base64.strict_encode64("bool=httpd_can_network_relay val=1 old_val=0")
    request["events"][0]["records"] << record
    post "/api/v1/events", params: request.to_json, headers: headers
    expect(RawEvent.last.boolean_changes.map { |change| change["name"] }).to eq(%w[httpd_can_network_connect httpd_can_network_relay])
    request = boolean_change_request
    request["events"][0]["records"][0]["payload"] = Base64.strict_encode64("op=unrelated res=1")
    post "/api/v1/events", params: request.to_json, headers: headers
    expect(response).to have_http_status(:unprocessable_content)
  end

  it "persists evidence and enqueues policy-question registration outside ingestion" do
    bytes = "test policy bytes"
    identity = "sha256:#{Digest::SHA256.hexdigest(bytes)}"
    heartbeat = heartbeat_request
    heartbeat["host"]["selinux"]["policy_identity"] = identity
    post "/api/v1/heartbeat", params: heartbeat.to_json, headers: headers
    PolicyArtifact.create!(policy_identity: identity, artifact: bytes, artifact_size: bytes.bytesize)
    request = ingest_request(raw_payload: avc_payload("/srv/test", ["getattr"]))

    expect {
      post "/api/v1/events", params: request.to_json, headers: headers
    }.to have_enqueued_job(RequestPolicyFactsJob).exactly(1).times

    expect(response).to have_http_status(:accepted)
    expect(RawEvent.count).to eq(1)
    expect(Occurrence.count).to eq(1)
    expect(PolicyFact.count).to eq(0)
  end

  it "retains AVC evidence when its asynchronous policy evaluator fails" do
    bytes = "test policy bytes"
    identity = "sha256:#{Digest::SHA256.hexdigest(bytes)}"
    heartbeat = heartbeat_request
    heartbeat["host"]["selinux"]["policy_identity"] = identity
    post "/api/v1/heartbeat", params: heartbeat.to_json, headers: headers
    PolicyArtifact.create!(policy_identity: identity, artifact: bytes, artifact_size: bytes.bytesize)
    allow(PolicyRuleEvaluator).to receive(:call).and_raise("evaluator failed")

    perform_enqueued_jobs do
      post "/api/v1/events", params: ingest_request(raw_payload: avc_payload("/srv/test", ["getattr"])).to_json, headers: headers
    end

    expect(response).to have_http_status(:accepted)
    expect(RawEvent.count).to eq(1)
    expect(Occurrence.count).to eq(1)
    expect(PolicyFact.first).to have_attributes(status: "error", error_message: "evaluator failed")
  end

  it "retains AVC evidence while the exact policy artifact is still unavailable" do
    identity = "sha256:" + "a" * 64
    heartbeat = heartbeat_request
    heartbeat["host"]["selinux"]["policy_identity"] = identity
    post "/api/v1/heartbeat", params: heartbeat.to_json, headers: headers

    expect {
      perform_enqueued_jobs do
        post "/api/v1/events", params: ingest_request(raw_payload: avc_payload("/srv/test", ["getattr"])).to_json, headers: headers
      end
    }.not_to have_enqueued_job(EvaluatePolicyFactJob)

    expect(response).to have_http_status(:accepted)
    expect(RawEvent.count).to eq(1)
    expect(Occurrence.count).to eq(1)
    expect(PolicyFact.first).to have_attributes(status: "pending", policy_identity: identity)
  end

  it "does not refresh heartbeat configuration freshness with event traffic" do
    heartbeat = heartbeat_request
    post "/api/v1/heartbeat", params: heartbeat.to_json, headers: headers
    observation = HostSnapshotObservation.last
    observation.update!(last_received_at: 1.hour.ago)

    post "/api/v1/events", params: ingest_request.to_json, headers: headers

    expect(installation.reload.last_seen_at).to be > 1.minute.ago
    expect(installation.bound_host.last_seen_at).to be > 1.minute.ago
    expect(observation.reload).to be_stale
  end

  it "does not refresh stale port inventory with event traffic" do
    heartbeat = heartbeat_request
    heartbeat["host"]["selinux"]["policy"] = { "port_inventory" => { "status" => "observed", "local_classification_status" => "observed", "mappings" => [{ "type" => "http_port_t", "protocol" => "tcp", "ports" => [{ "start" => 80, "end" => 80, "provenance" => "not_confirmed_custom" }] }] } }
    post "/api/v1/heartbeat", params: heartbeat.to_json, headers: headers
    observation = HostSnapshotObservation.last
    observation.update!(last_received_at: 1.hour.ago)

    event = ingest_request
    post "/api/v1/events", params: event.to_json, headers: headers

    expect(observation.reload).to be_stale
    expect(installation.reload.bound_host.current_snapshot.details.dig("selinux", "policy", "port_inventory", "mappings", 0, "ports", 0, "start")).to eq(80)
    expect(RawEvent.last.host_snapshot.details.dig("selinux", "policy", "port_inventory", "mappings", 0, "ports", 0, "start")).to eq(80)
  end

  it "accepts proctitle records from the live audit stream" do
    request = ingest_request(raw_payload: avc_payload("/srv/test", ["read"]))
    record = request["events"][0]["records"][0].dup
    record["position"] = 1
    record["type"] = "proctitle"
    record["type_name"] = "PROCTITLE"
    request["events"][0]["records"] << record

    post "/api/v1/events", params: request.to_json, headers: headers

    expect(response).to have_http_status(:accepted)
    expect(RawAuditRecord.where(record_type: 1327).count).to eq(1)
  end

  it "rejects conflicting duplicate evidence" do
    request = ingest_request
    post "/api/v1/events", params: request.to_json, headers: headers
    expect(response).to have_http_status(:accepted)

    request["events"][0]["records"][0]["payload"] = Base64.strict_encode64("avc: changed")
    post "/api/v1/events", params: request.to_json, headers: headers
    expect(response).to have_http_status(:unprocessable_content)
    expect(RawEvent.count).to eq(1)
    expect(RawAuditRecord.first.payload).to eq("avc: denied")
  end

  it "rejects an invalid batch without persistence" do
    request = ingest_request
    request["events"][0]["records"][0]["sequence"] = 99

    post "/api/v1/events", params: request.to_json, headers: headers
    expect(response).to have_http_status(:unprocessable_content)
    expect(RawEvent.count).to eq(0)
    expect(Host.count).to eq(0)
    expect(HostSnapshot.count).to eq(0)
  end

  %w[malformed_avc valid_boundary malformed_boundary conflict unknown_type invalid_envelope].each do |failure|
    it "records the current atomic batch failure boundary for #{failure}" do
      request = ingest_request(sequence: 8123, raw_payload: avc_payload("/srv/first", ["read"]))
      middle = ingest_request["events"][0]
      case failure
      when "malformed_avc"
        middle["records"][0]["position"] = 99
      when "valid_boundary"
        request["events"] = boolean_change_request["events"]
        middle["records"][0]["position"] = 99
        middle["audit_event"]["sequence"] = 8125
        middle["records"][0]["sequence"] = 8125
      when "malformed_boundary"
        middle = boolean_change_request["events"][0]
        middle["records"][0]["position"] = 99
        request["events"] = []
      when "conflict"
        post "/api/v1/events", params: ingest_request.to_json, headers: headers
        expect(response).to have_http_status(:accepted)
        middle["records"][0]["payload"] = Base64.strict_encode64("changed evidence")
      when "unknown_type"
        middle["records"][0].merge!("type" => "unregistered", "type_name" => "unregistered")
      when "invalid_envelope"
        request["boot_id"] = ""
      end
      request["events"] += [middle, ingest_request(sequence: 8126)["events"][0]]
      retained = [RawEvent.count, RawAuditRecord.count, Occurrence.count]
      expect {
        post "/api/v1/events", params: request.to_json, headers: headers
      }.not_to have_enqueued_job(RequestPolicyFactsJob)
      expect(response).to have_http_status(:unprocessable_content)
      expect([RawEvent.count, RawAuditRecord.count, Occurrence.count]).to eq(retained)
      expect(RawEvent.state_transitions.count).to eq(0)
      expect(JSON.parse(response.body).dig("error", "details")).to include(
        hash_including("code" => failure == "conflict" ? "conflicting_duplicate" : failure == "unknown_type" ? "invalid_type" : failure == "invalid_envelope" ? "required" : "position_mismatch"))
      if failure == "valid_boundary"
        repaired = request.deep_dup
        repaired["events"].delete_at(1)
        post "/api/v1/events", params: repaired.to_json, headers: headers
        expect(response).to have_http_status(:accepted)
        expect(RawEvent.state_transitions.sole.transition_type).to eq("boolean_change")
        expect(Occurrence.sole.raw_event.checkpoint_invalidated_fields).to eq(CheckpointTrust.fields_for("boolean_change"))
      end
    end
  end

  it "rejects the starvation simulation's AVC-category poison with no AVC record before persistence" do
    request = ingest_request(sequence: 8123)
    poison = ingest_request["events"][0]
    poison["records"][0].merge!("type" => "syscall", "type_name" => "SYSCALL", "payload" => Base64.strict_encode64("syscall=188 success=no exit=-22"))
    request["events"] += [poison, ingest_request(sequence: 8125)["events"][0]]
    post "/api/v1/events", params: request.to_json, headers: headers
    expect(response).to have_http_status(:unprocessable_content)
    expect(JSON.parse(response.body).dig("error", "details")).to eq([{"path" => "events[1].category", "code" => "avc_record_required"}])
    expect([RawEvent.count, Occurrence.count]).to eq([0, 0])
  end

  {
    "policy_load" => ["mac_policy_load", "MAC_POLICY_LOAD", "res=1"],
    "boolean_change" => ["mac_config_change", "MAC_CONFIG_CHANGE", "bool=httpd_can_network_connect val=0 old_val=1"],
    "enforcement_change" => ["mac_status", "MAC_STATUS", "enforcing=0 old_enforcing=1 enabled=1 old-enabled=1 lsm=selinux res=1"],
    "port_change" => ["user_mac_config_change", "USER_MAC_CONFIG_CHANGE", "msg='resrc=port op=add proto=6 lport=12345 tcontext=system_u:object_r:http_port_t:s0 res=success'"],
    "file_context_change" => ["user_mac_config_change", "USER_MAC_CONFIG_CHANGE", 'msg=\'resrc=fcontext op=add tglob="/srv/example(/.*)?" ftype=any tcontext=system_u:object_r:httpd_sys_content_t: res=success\'']
  }.each do |family, (type, name, payload)|
    it "exposes and later corrects stale trust if a rejected #{family} is bypassed by an unmasked AVC" do
      checkpoint = boolean_checkpoint(1)
      bytes = "batch-isolation policy fixture"
      identity = "sha256:#{Digest::SHA256.hexdigest(bytes)}"
      checkpoint["host"]["selinux"]["policy_identity"] = identity
      checkpoint["host"]["selinux"].merge!("enforcement" => "enforcing", "policy" => {
        "port_inventory" => { "status" => "observed", "mappings" => [] },
        "file_context_mappings_status" => "observed", "file_contexts" => [], "local_file_context_mappings" => [], "file_context_equivalences" => []
      })
      post "/api/v1/heartbeat", params: checkpoint.to_json, headers: headers
      boundary = policy_load_request
      boundary["events"][0]["records"][0].merge!("type" => type, "type_name" => name, "payload" => Base64.strict_encode64(payload))
      avc = ingest_request(sequence: 8126, raw_payload: avc_payload("/srv/after", ["read"]))
      timestamp = "2026-09-13T17:30:12.128456Z"
      avc["events"][0]["audit_event"]["timestamp"] = timestamp
      avc["events"][0]["records"][0]["timestamp"] = timestamp
      batch = boundary.deep_dup
      batch["events"][0]["records"][0]["position"] = 99
      batch["events"] += avc["events"]
      post "/api/v1/events", params: batch.to_json, headers: headers
      expect(response).to have_http_status(:unprocessable_content)
      expect(RawEvent.count).to eq(0)

      # Emulate naive isolation through existing atomic single-event requests.
      post "/api/v1/events", params: avc.to_json, headers: headers
      event = RawEvent.sole
      occurrence = Occurrence.sole
      digest = event.evidence_digest
      expect(event.checkpoint_invalidated_fields).to eq([])
      expect(event.checkpoint_policy_identity).to eq(checkpoint.dig("host", "selinux", "policy_identity"))
      expect(event.checkpoint_enforcement_mode).to eq("enforcing")
      CheckpointTrust.fields_for(family).each { |field| expect(event.checkpoint_trust.trusted?(field)).to eq(true) }
      host = event.host
      PolicyArtifactIngestion.call(host: host, policy_identity: identity, bytes: bytes)
      PolicyFactRequest.for_event(event)
      expect(PolicyFact.count).to eq(1)

      post "/api/v1/events", params: boundary.to_json, headers: headers
      expect(response).to have_http_status(:accepted)
      expect(RawEvent.state_transitions.sole.transition_type).to eq(family)
      expect(event.reload.checkpoint_invalidated_fields).to eq(CheckpointTrust.fields_for(family))
      CheckpointTrust.fields_for(family).each { |field| expect(event.checkpoint_trust.trusted?(field)).to eq(false) }
      if CheckpointTrust.fields_for(family).include?("policy_identity")
        expect { PolicyArtifactIngestion.call(host: host, policy_identity: identity, bytes: bytes) }.to raise_error(PolicyArtifactIngestion::HostIdentityMismatch)
      else
        expect(PolicyArtifactIngestion.call(host: host, policy_identity: identity, bytes: bytes)).to be_persisted
      end
      expect(event.evidence_digest).to eq(digest)
      expect(occurrence.reload.host_snapshot.nil?).to eq(CheckpointTrust::WITHHELD_ASSOCIATIONS.include?(family))
      expect(PolicyFact.count).to eq(1) # Historical exact questions are not deleted.
      ProcessRawEvent.call(event)
      expect(occurrence.reload.host_snapshot.nil?).to eq(CheckpointTrust::WITHHELD_ASSOCIATIONS.include?(family))
      replay = boundary.deep_dup
      replay["events"] += avc["events"]
      [replay, replay.merge("events" => replay["events"].reverse), boundary].each do |retry_request|
        post "/api/v1/events", params: retry_request.to_json, headers: headers
        expect(response).to have_http_status(:accepted)
      end
      expect([RawEvent.count, Occurrence.count, PolicyFact.count]).to eq([2, 1, 1])
    end
  end

  it "can return a processing 422 after raw batch commit and recover through idempotent retry" do
    request = ingest_request(sequence: 8123, raw_payload: avc_payload("/srv/first", ["read"]))
    request["events"] += [ingest_request["events"][0], ingest_request(sequence: 8125)["events"][0]]
    allow(ProcessRawEvent).to receive(:call).and_wrap_original do |original, event|
      raise ActiveRecord::RecordInvalid.new(Occurrence.new) if event.audit_sequence == 8124
      original.call(event)
    end
    post "/api/v1/events", params: request.to_json, headers: headers
    expect(response).to have_http_status(:unprocessable_content)
    expect([RawEvent.count, Occurrence.count]).to eq([3, 1])
    expect(JSON.parse(response.body)["error"]).not_to have_key("details")
    allow(ProcessRawEvent).to receive(:call).and_call_original
    post "/api/v1/events", params: request.to_json, headers: headers
    expect(response).to have_http_status(:accepted)
    expect([RawEvent.count, Occurrence.count]).to eq([3, 3])
  end

  it "rejects a malformed payload for direct service callers before the persistence seam" do
    request = ingest_request
    request["events"][0]["records"][0]["payload"] = 42
    expect_any_instance_of(IngestEvents).not_to receive(:persist_raw_envelope!)
    expect { IngestEvents.new(organization: organization, payload: request).call }.to raise_error(IngestEvents::InvalidRequest) { |error|
      expect(error.details).to eq([{"path" => "events[0].records[0].payload", "code" => "invalid_type"}])
    }
    expect(RawEvent.count).to eq(0)
  end

  it "returns structured validation through exception-rendering Rails middleware" do
    request = ingest_request
    request["events"][0]["records"][0]["payload"] = 123
    expect_any_instance_of(IngestEvents).not_to receive(:persist_raw_envelope!)
    expect(Host).not_to receive(:find_for_ingestion!)
    with_exception_rendering do
      post "/api/v1/events", params: request.to_json, headers: headers.merge("ACCEPT" => "application/json")
    end
    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body.dig("error", "phase")).to eq("pre_persistence")
    expect([Host.count, RawEvent.count, RawAuditRecord.count, Occurrence.count]).to eq([0, 0, 0, 0])
  end

  [123, nil, {}, [], true, "not base64!", "", Base64.strict_encode64(" ")].each do |payload|
    context "payload #{payload.inspect}" do
      let(:malformed_request) do
        request = ingest_request(sequence: 8123)
        middle = ingest_request["events"][0]
        middle["records"][0]["payload"] = payload
        request["events"] += [middle, ingest_request(sequence: 8125)["events"][0]]
        request
      end
      let(:expected_details) do
        code = if payload.nil? || payload == "" || payload == Base64.strict_encode64(" ")
          "required"
        elsif payload.is_a?(String)
          "invalid_base64"
        else
          "invalid_type"
        end
        [{"path" => "events[1].records[0].payload", "code" => code}]
      end
      include_examples "indexed pre-persistence validation"
    end
  end

  {
    "event object" => ["events[0]", "object_required", ->(r) { r["events"][0] = true }],
    "audit identity object" => ["events[0].audit_event", "object_required", ->(r) { r["events"][0]["audit_event"] = [] }],
    "record array" => ["events[0].records", "array_required", ->(r) { r["events"][0]["records"] = {} }],
    "record object" => ["events[0].records[0]", "object_required", ->(r) { r["events"][0]["records"][0] = 1 }],
    "serial type" => ["events[0].audit_event.sequence", "invalid_integer", ->(r) { r["events"][0]["audit_event"]["sequence"] = {} }],
    "timestamp type" => ["events[0].agent_received_at", "invalid_type", ->(r) { r["events"][0]["agent_received_at"] = true }],
    "timestamp value" => ["events[0].agent_received_at", "invalid_timestamp", ->(r) { r["events"][0]["agent_received_at"] = "not-time" }],
    "record position type" => ["events[0].records[0].position", "invalid_integer", ->(r) { r["events"][0]["records"][0]["position"] = "0" }],
    "type name shape" => ["events[0].records[0].type_name", "invalid_type", ->(r) { r["events"][0]["records"][0]["type_name"] = {} }],
    "category value" => ["events[0].category", "unknown_category", ->(r) { r["events"][0]["category"] = "unregistered" }],
    "unknown type" => ["events[0].records[0].type", "invalid_type", ->(r) { r["events"][0]["records"][0]["type"] = "unregistered" }],
    "SELINUX_ERR conflict" => ["events[0].records[1].type_name", "record_type_name_mismatch", ->(r) { r["events"][0]["records"][1].merge!("type" => 1401, "type_name" => "AVC") }],
    "duplicate position" => ["events[0].records[1].position", "position_mismatch", ->(r) { r["events"][0]["records"][1]["position"] = 0 }]
  }.each do |name, (path, code, mutate)|
    context name do
      let(:malformed_request) { selinux_error_request.tap { |request| mutate.call(request) } }
      let(:expected_details) { [{"path" => path, "code" => code}] }
      include_examples "indexed pre-persistence validation"
    end
  end

  %w[MAC_POLICY_LOAD MAC_CONFIG_CHANGE MAC_STATUS port fcontext].each do |family|
    context "malformed metadata in #{family}" do
      let(:malformed_request) do
        request = policy_load_request
        type, payload = case family
        when "MAC_POLICY_LOAD" then ["mac_policy_load", "res=1"]
        when "MAC_CONFIG_CHANGE" then ["mac_config_change", "bool=httpd_can_network_connect val=0 old_val=1"]
        when "MAC_STATUS" then ["mac_status", "enforcing=0 old_enforcing=1 enabled=1 old-enabled=1 lsm=selinux res=1"]
        when "port" then ["user_mac_config_change", "msg='resrc=port op=add proto=6 lport=12345 tcontext=system_u:object_r:http_port_t:s0 res=success'"]
        else ["user_mac_config_change", 'msg=\'resrc=fcontext op=add tglob="/srv/test" ftype=any tcontext=system_u:object_r:httpd_sys_content_t: res=success\'']
        end
        request["events"][0]["records"][0].merge!("type" => type, "type_name" => type.upcase, "payload" => Base64.strict_encode64(payload))
        # Exercise both non-string supporting payload and array-index diagnostics.
        request["events"][0]["records"][1].merge!("position" => 12, "payload" => {})
        request["events"] += ingest_request(sequence: 8125)["events"]
        request
      end
      let(:expected_details) { [{"path" => "events[0].records[1].position", "code" => "position_mismatch"}, {"path" => "events[0].records[1].payload", "code" => "invalid_type"}] }
      include_examples "indexed pre-persistence validation"
    end
  end

  context "multiple malformed events" do
    let(:malformed_request) do
      request = ingest_request
      request["events"][0]["records"][0]["payload"] = 123
      second = ingest_request(sequence: 8125)["events"][0]
      second["records"][0]["position"] = 12
      request["events"] << second
      request
    end
    let(:expected_details) { [{"path" => "events[0].records[0].payload", "code" => "invalid_type"}, {"path" => "events[1].records[0].position", "code" => "position_mismatch"}] }
    include_examples "indexed pre-persistence validation"
  end

  %w[agent events host checkpoint schema mixed].each do |shape|
    context "envelope #{shape} failure" do
      let(:expected_status) { 422 }
      let(:expected_entries) { 0 }
      let(:submit_failure) do
        -> {
          request = ingest_request
          case shape
          when "agent" then request["agent"] = []
          when "events" then request["events"] = {}
          when "host" then request["host_id"] = true
          when "checkpoint" then request["host_observed_at"] = {}
          when "schema" then request["schema_version"] = 3
          when "mixed"
            request["boot_id"] = ""
            request["events"][0]["records"][0]["payload"] = 123
          end
          before = ingestion_state
          post "/api/v1/events", params: request.to_json, headers: headers
          expect(ingestion_state).to eq(before)
        }
      end
      include_examples "no pre-persistence guarantee"
    end
  end

  %w[authentication malformed_json conflict processing indexed_processing transient validator_bug].each do |failure|
    context "non-validation #{failure}" do
      let(:expected_status) { failure == "authentication" ? 401 : failure == "malformed_json" ? 400 : %w[transient validator_bug].include?(failure) ? 500 : 422 }
      let(:expected_entries) { %w[conflict processing indexed_processing transient].include?(failure) ? 1 : 0 }
      let(:submit_failure) do
        -> {
          request = ingest_request(sequence: 8123)
          case failure
          when "authentication"
            post "/api/v1/events", params: request.to_json, headers: headers.except("Authorization")
          when "malformed_json"
            post "/api/v1/events", params: "{", headers: headers
          when "conflict"
            before = ingestion_state
            conflict = ingest_request(sequence: 8000)["events"][0]
            conflict["records"][0]["payload"] = Base64.strict_encode64("changed supporting evidence")
            request["events"] << conflict
            attempts = 0
            allow_any_instance_of(IngestEvents).to receive(:persist_event!).and_wrap_original { |original, *args| attempts += 1; original.call(*args) }
            post "/api/v1/events", params: request.to_json, headers: headers
            expect(attempts).to eq(2)
            expect(ingestion_state).to eq(before)
            expect(response.parsed_body.dig("error", "details")).to eq([{"path" => "events", "code" => "conflicting_duplicate"}])
          when "processing", "indexed_processing"
            request["events"] += [ingest_request["events"][0], ingest_request(sequence: 8125)["events"][0]]
            allow(ProcessRawEvent).to receive(:call).and_wrap_original do |original, event|
              if event.audit_sequence == 8124
                if failure == "indexed_processing"
                  raise IngestEvents::InvalidRequest, [{"path" => "events[1].records[0].payload", "code" => "invalid_type"}]
                end
                raise ActiveRecord::RecordInvalid.new(Occurrence.new)
              end
              original.call(event)
            end
            post "/api/v1/events", params: request.to_json, headers: headers
            expect([RawEvent.count, Occurrence.count]).to eq([4, 2]) # Seed + three new raw / one processed.
          else
            if failure == "transient"
              allow(Host).to receive(:find_for_ingestion!).and_raise(ActiveRecord::ConnectionNotEstablished)
            else
              allow_any_instance_of(IngestEvents).to receive(:validate!).and_raise("unexpected validator defect")
            end
            with_exception_rendering { post "/api/v1/events", params: request.to_json, headers: headers.merge("ACCEPT" => "application/json") }
          end
        }
      end
      include_examples "no pre-persistence guarantee"
    end
  end

  it "preserves the existing absence of a per-record size cap and filters payloads from Rails parameter logs" do
    payload = "avc: denied " + "x" * 65_536
    post "/api/v1/events", params: ingest_request(raw_payload: payload).to_json, headers: headers
    expect(response).to have_http_status(:accepted)
    expect(RawAuditRecord.sole.payload).to eq(payload)
    filtered = ActiveSupport::ParameterFilter.new(Rails.application.config.filter_parameters).filter({"records" => [{"payload" => Base64.strict_encode64(payload)}]})
    expect(filtered["records"][0]["payload"]).to eq("[FILTERED]")
  end

  it "accepts different hosts with the same ingestion key" do
    post "/api/v1/events", params: ingest_request.to_json, headers: headers
    expect(response).to have_http_status(:accepted)

    post "/api/v1/events", params: ingest_request(host_id: "another-host").to_json, headers: headers
    expect(response).to have_http_status(:accepted)
    expect(Host.count).to eq(2)
    expect(AgentInstallation.count).to eq(2)
  end

  it "rejects missing or invalid ingestion keys" do
    post "/api/v1/events", params: ingest_request.to_json, headers: { "CONTENT_TYPE" => "application/json" }
    expect(response).to have_http_status(:unauthorized)

    post "/api/v1/events", params: ingest_request.to_json, headers: { "CONTENT_TYPE" => "application/json", "Authorization" => "Bearer wrong" }
    expect(response).to have_http_status(:unauthorized)
  end

  it "fails clearly unless the deployment has exactly one organization" do
    Organization.delete_all
    post "/api/v1/events", params: ingest_request.to_json, headers: headers
    expect(response).to have_http_status(:service_unavailable)
    expect(response.parsed_body.dig("error", "code")).to eq("ingestion_unavailable")

    Organization.create!(name: "first")
    Organization.create!(name: "second")
    post "/api/v1/events", params: ingest_request.to_json, headers: headers
    expect(response).to have_http_status(:service_unavailable)
  end

  it "does not use a host identity as authentication" do
    post "/api/v1/events", params: ingest_request(host_id: "known-host").to_json, headers: headers
    expect(response).to have_http_status(:accepted)

    post "/api/v1/events", params: ingest_request(host_id: "known-host").to_json, headers: { "CONTENT_TYPE" => "application/json" }
    expect(response).to have_http_status(:unauthorized)
  end

  it "rejects malformed protocol values" do
    invalid_requests = [
      ingest_request.tap { |r| r["events"][0]["audit_event"]["timestamp"] = "not-a-time" },
      ingest_request.tap { |r| r["events"][0]["agent_received_at"] = "not-a-time" },
      ingest_request.tap { |r| r["events"][0]["audit_event"]["sequence"] = "not-an-integer" },
      ingest_request.tap { |r| r["events"][0]["records"][0].delete("type") },
      ingest_request.tap { |r| r["events"][0]["records"][0]["timestamp"] = "not-a-time" }
    ]

    invalid_requests.each do |request|
      post "/api/v1/events", params: request.to_json, headers: headers
      expect(response).to have_http_status(:unprocessable_content)
    end
    expect(RawEvent.count).to eq(0)
  end

  it "accepts concurrent identical delivery exactly once" do
    request = ingest_request
    results = 2.times.map do
      Thread.new { IngestEvents.new(organization: organization, payload: request).call }
    end

    results.each { |thread| expect { thread.value }.not_to raise_error }
    expect(RawEvent.count).to eq(1)
    expect(Host.count).to eq(1)
    expect(AgentInstallation.count).to eq(1)
  end

  it "turns concurrent conflicting delivery into one controlled conflict" do
    first = ingest_request
    second = ingest_request
    second["events"][0]["records"][0]["payload"] = Base64.strict_encode64("changed")
    results = [first, second].map do |request|
      Thread.new do
        IngestEvents.new(organization: organization, payload: request).call
        :accepted
      rescue IngestEvents::EvidenceConflict
        :conflict
      end
    end.map(&:value)

    expect(results.count(:conflict)).to eq(1)
    expect(RawEvent.count).to eq(1)
  end

  it "groups equivalent v3 denials across hosts without merging distinct permission sets" do
    post "/api/v1/events", params: ingest_request(host_id: "host-a", raw_payload: avc_payload("/srv/a", %w[read open])).to_json, headers: headers
    expect(response).to have_http_status(:accepted)
    post "/api/v1/events", params: ingest_request(host_id: "host-b", raw_payload: avc_payload("/srv/b", %w[open read])).to_json, headers: headers
    expect(response).to have_http_status(:accepted)

    expect(RawEvent.count).to eq(2)
    expect(Occurrence.count).to eq(2)
    expect(Issue.count).to eq(1)
    expect(Issue.pluck(:fingerprint_version).uniq).to eq([3])
    grouped_issue = Issue.all.find { |issue| issue.permissions == %w[open read] }
    expect(grouped_issue).to be_present
    expect(grouped_issue.occurrences_count).to eq(2)

    post "/api/v1/events", params: ingest_request(host_id: "host-b", sequence: 8125, raw_payload: avc_payload("/srv/b", ["read"])).to_json, headers: headers
    expect(response).to have_http_status(:accepted)
    expect(Issue.count).to eq(2)
    expect(Issue.where(fingerprint_version: 3).pluck(:permissions)).to contain_exactly(["open", "read"], ["read"])
  end

  it "keeps one occurrence and one issue for a multi-permission AVC" do
    post "/api/v1/events", params: ingest_request(raw_payload: avc_payload("/srv/test", %w[read open read])).to_json, headers: headers

    expect(response).to have_http_status(:accepted)
    expect(Occurrence.count).to eq(1)
    expect(Issue.count).to eq(1)
    expect(Issue.first.permissions).to eq(%w[open read])
  end

  it "creates separate v3 issues for equivalent tuple bind and connect events" do
    bind = avc_payload("/srv/test", ["name_bind"]).sub("tclass=file", "tclass=tcp_socket")
    connect = bind.sub("name_bind", "name_connect")

    post "/api/v1/events", params: ingest_request(sequence: 8124, raw_payload: bind).to_json, headers: headers
    post "/api/v1/events", params: ingest_request(sequence: 8125, raw_payload: connect).to_json, headers: headers

    expect(response).to have_http_status(:accepted)
    expect(Issue.where(fingerprint_version: 3).count).to eq(2)
    expect(Issue.where(fingerprint_version: 3).pluck(:permissions)).to contain_exactly(["name_bind"], ["name_connect"])
  end

  it "reopens resolved issues but keeps ignored issues ignored" do
    request = ingest_request(raw_payload: avc_payload("/srv/test", ["read"]))
    post "/api/v1/events", params: request.to_json, headers: headers
    issue = Issue.first

    issue.transition_to!("resolved")
    post "/api/v1/events", params: ingest_request(sequence: 8125, raw_payload: avc_payload("/srv/test", ["read"])).to_json, headers: headers
    expect(issue.reload).to have_attributes(status: "open", regressions_count: 1)

    issue.transition_to!("ignored")
    post "/api/v1/events", params: ingest_request(sequence: 8126, raw_payload: avc_payload("/srv/test", ["read"])).to_json, headers: headers
    expect(issue.reload.status).to eq("ignored")
  end

  it "collapses malformed bearer credentials to unauthorized" do
    ["Bearer", "Basic test-ingestion-key", "Bearer test-ingestion-key extra"].each do |authorization|
      post "/api/v1/events", params: ingest_request.to_json, headers: { "CONTENT_TYPE" => "application/json", "Authorization" => authorization }
      expect(response).to have_http_status(:unauthorized)
    end
  end

  def installation
    Host.find_by!(external_id: "host-1").agent_installations.sole
  end

  def ingest_request(host_id: "host-1", sequence: 8124, raw_payload: "avc: denied")
    timestamp = "2026-09-13T17:30:12.123456Z"
    {
      "schema_version" => 4,
      "agent" => { "version" => "0.1.0" },
      "host_id" => host_id,
      "boot_id" => "boot-1",
      "host_observed_at" => "2026-09-13T17:29:00.000000Z",
      "events" => [{
        "category" => "avc",
        "audit_event" => { "timestamp" => timestamp, "sequence" => sequence },
        "agent_received_at" => timestamp,
        "completion_reason" => "eoe",
        "records" => [{
          "position" => 0,
          "type" => "avc",
          "type_name" => "AVC",
          "timestamp" => timestamp,
          "sequence" => sequence,
          "payload" => Base64.strict_encode64(raw_payload)
        }]
      }]
    }
  end

  def policy_load_request(success: true)
    request = ingest_request
    event = request.fetch("events").first
    event["category"] = "selinux_administrative"
    event["records"] = [
      ["mac_policy_load", "MAC_POLICY_LOAD", "auid=4294967295 res=#{success ? 1 : 0}"],
      ["syscall", "SYSCALL", "success=#{success ? "yes" : "no"} comm=\"load_policy\""],
      ["proctitle", "PROCTITLE", "proctitle=2F7362696E2F6C6F61645F706F6C696379"]
    ].each_with_index.map do |(type, type_name, payload), position|
      {
        "position" => position,
        "type" => type,
        "type_name" => type_name,
        "timestamp" => event.dig("audit_event", "timestamp"),
        "sequence" => event.dig("audit_event", "sequence"),
        "payload" => Base64.strict_encode64(payload)
      }
    end
    request
  end

  def selinux_error_request
    request = ingest_request(raw_payload: 'avc: denied { mac_admin } for pid=10 comm="chcon" capability=33 scontext=unconfined_u:unconfined_r:unconfined_t:s0 tcontext=unconfined_u:unconfined_r:unconfined_t:s0 tclass=capability2 permissive=0')
    event = request["events"][0]
    [["selinux_err", "SELINUX_ERR", "op=setxattr invalid_context=unconfined_u:object_r:secentral_nonexistent_t:s0"],
     ["syscall", "SYSCALL", 'arch=c000003e syscall=188 success=no exit=-22 comm="chcon" exe="/usr/bin/chcon"'],
     ["proctitle", "PROCTITLE", "proctitle=6368636F6E"],
     ["eoe", "EOE", ""]].each do |type, name, payload|
      event["records"] << event["records"][0].merge("position" => event["records"].size, "type" => type, "type_name" => name,
        "payload" => Base64.strict_encode64("audit(1789320612.123456:8124): #{payload}"))
    end
    request
  end

  def boolean_change_request(old_value: 1, new_value: 0, result: nil)
    request = policy_load_request
    record = request["events"][0]["records"][0]
    record.merge!("type" => "mac_config_change", "type_name" => "MAC_CONFIG_CHANGE",
      "payload" => Base64.strict_encode64("bool=httpd_can_network_connect val=#{new_value} old_val=#{old_value} auid=0 ses=535#{result ? " res=#{result}" : ""}"))
    request
  end

  def boolean_checkpoint(value)
    checkpoint = heartbeat_request
    checkpoint["host"]["selinux"].merge!("policy_identity" => "sha256:" + (value == 1 ? "a" : "b") * 64,
      "booleans" => [{ "name" => "httpd_can_network_connect", "current" => value == 1, "status" => "observed" }])
    checkpoint
  end

  def connect_payload
    'avc: denied { name_connect } for pid=10 comm="httpd" dest=12345 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:unreserved_port_t:s0 tclass=tcp_socket permissive=0'
  end

  def expected_context_request(event_request, path:, status: "resolved", reason: nil)
    event = event_request.fetch("events").first
    observation = {
      "path" => path,
      "object_class" => "file",
      "file_type" => "file",
      "expected_context" => "system_u:object_r:httpd_sys_content_t:s0",
      "observed_at" => "2026-09-13T17:30:13.000000Z",
      "resolver" => "matchpathcon",
      "status" => status
    }
    observation["reason"] = reason if reason
    {
      "schema_version" => 1,
      "agent" => event_request.fetch("agent"),
      "host_id" => event_request.fetch("host_id"),
      "boot_id" => event_request.fetch("boot_id"),
      "host_observed_at" => event_request.fetch("host_observed_at"),
      "audit_event" => event.fetch("audit_event"),
      "observation" => observation
    }
  end

  def heartbeat_request
    {
      "schema_version" => 2,
      "agent" => { "version" => "0.1.0" },
      "host_observed_at" => "2026-09-13T17:29:00.000000Z",
      "host" => { "id" => "host-1", "hostname" => "server01", "boot_id" => "boot-1", "selinux" => { "enabled" => true, "enforcement" => "enforcing" } }
    }
  end

  def avc_payload(path, permissions)
    "avc: denied { #{permissions.join(' ')} } for pid=10 comm=\"httpd\" exe=\"/usr/sbin/httpd\" path=\"#{path}\" scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:default_t:s0 tclass=file"
  end
end
