require "rails_helper"

RSpec.describe "Monitored-server SELinux activity", type: :request do
  let(:organization) { Organization.create!(name: "activity") }
  let(:base) { Time.utc(2026, 10, 1, 14) }
  let(:host) { Host.find_by!(organization: organization, external_id: "activity-host") }

  before do
    sign_in_operator
    Host.create!(organization: organization, external_id: "activity-host")
  end

  after do
    Occurrence.delete_all
    NormalizedDenial.delete_all
    Issue.delete_all
    RawAuditRecord.delete_all
    RawEvent.delete_all
    HostSnapshotObservation.delete_all
    HostSnapshot.delete_all
    AgentInstallation.delete_all
    Host.delete_all
    Organization.delete_all
  end

  it "projects a policy-load boundary and its separately observed reconciliation checkpoint" do
    checkpoint(0, true)
    event = administrative(2, 10, type: "policy_load")
    checkpoint(4, false)
    item = page.fetch("items").sole
    expect(item).to include("id" => event.id, "evidence_class" => "observed_transition", "transition_type" => "policy_load", "boundary_established" => true)
    expect(item["previous_checkpoint"]).to include("evidence_class" => "observed_checkpoint", "policy_identity" => identity(true))
    expect(item.dig("reconciliation", "status")).to eq("reconciled")
    expect(item.dig("reconciliation", "checkpoint")).to include("evidence_class" => "observed_checkpoint", "policy_identity" => identity(false))
    expect(item).not_to have_key("policy_identity")
    expect(item).not_to have_key("evidence")
  end

  [[true, false], [false, true]].each do |old_value, new_value|
    it "projects #{old_value ? 'On' : 'Off'} -> #{new_value ? 'On' : 'Off'} and identifies only the unresolved window AVC" do
      checkpoint(0, old_value)
      transition = administrative(2, 10, changes: [["httpd_can_network_connect", old_value, new_value]])
      window = avc(3, 11)
      checkpoint(4, new_value)
      later = avc(5, 12, checkpoint_at: 4)
      item = page.fetch("items").sole
      expect(item["actor"]).to include("login_uid" => 0, "execution_uid" => 0, "pid" => 1402, "context" => "system_u:system_r:sysadm_t:s0", "command" => "setsebool")
      expect(item["boolean_changes"]).to eq([{ "name" => "httpd_can_network_connect", "old_value" => old_value,
        "new_value" => new_value, "state_change_established" => true }])
      expect(item["window_avc_count"]).to eq(1)
      expect(item.dig("reconciliation", "checkpoint", "booleans")).to eq([{ "name" => "httpd_can_network_connect", "value" => new_value }])
      expect(window.reload.host_snapshot).to be_nil
      expect(later.host_snapshot).to be_present

      get "/api/v1/hosts/#{host.id}/selinux-activity/#{transition.id}"
      detail = JSON.parse(response.body).fetch("item")
      expect(detail["window_occurrences"].map { |occurrence| occurrence["id"] }).to eq([window.id])
      expect(detail["actor"]).to include("login_uid" => 0, "session" => 535, "executable" => "/usr/sbin/setsebool", "proctitle" => "setsebool httpd_can_network_connect off")
      expect(detail.dig("evidence", "records").map { |record| record["type_name"] }).to eq(%w[MAC_CONFIG_CHANGE SYSCALL PROCTITLE EOE])
      expect(page(occurrence_id: window.id).fetch("items").sole["id"]).to eq(transition.id)
      expect(page(occurrence_id: later.id).fetch("items")).to be_empty
    end
  end

  it "groups all boolean records of one audit identity, preserving original record order" do
    event = administrative(2, 10, changes: [["httpd_can_network_connect", true, false], ["httpd_can_network_relay", false, true]])
    item = page.fetch("items").sole
    expect(item["id"]).to eq(event.id)
    expect(item["boolean_changes"].map { |change| change["name"] }).to eq(%w[httpd_can_network_connect httpd_can_network_relay])
    expect(RawEvent.count).to eq(1)
    expect(Occurrence.count).to eq(0)
  end

  it "keeps unset and conflicting actor identifiers unknown on initial render" do
    event = administrative(2, 10)
    event.raw_audit_records.find_by!(record_type: 1300).update!(payload: 'auid=4294967295 uid=4294967295 pid=7 comm="other"')
    actor = page.fetch("items").sole.fetch("actor")
    expect(actor).to include("login_uid" => nil, "execution_uid" => nil, "pid" => 7, "command" => "other")
  end

  it "distinguishes failed boolean and policy-load history from successful boundaries" do
    administrative(2, 10, success: false)
    administrative(3, 11, type: "policy_load", success: false)
    items = page.fetch("items")
    expect(items).to all(include("evidence_class" => "administrative_history", "boundary_established" => false, "window_avc_count" => 0))
    expect(items.map { |item| item.dig("reconciliation", "status") }).to eq(%w[not_applicable not_applicable])
    expect(items.last["boolean_changes"].sole["state_change_established"]).to be(false)
  end

  it "renders audit chronology rather than transport order and deduplicates replay" do
    newer = administrative(3, 12)
    older = administrative(2, 11)
    tied = administrative(3, 10, changes: [["httpd_can_network_connect", false, true]])
    replay = administrative(2, 11)
    expect(replay.id).to eq(older.id)
    expect(page.fetch("items").map { |item| item["id"] }).to eq([newer.id, tied.id, older.id])
  end

  it "never synthesizes activity from snapshot-only drift" do
    checkpoint(0, true)
    checkpoint(4, false)
    expect(page.fetch("items")).to be_empty
    expect(HostSnapshot.count).to eq(2)
    expect(RawEvent.count).to eq(0)
  end

  it "does not fill an unobserved checkpoint boolean from the transition delta" do
    administrative(2, 10)
    checkpoint(4, false, booleans: [])
    value = page.fetch("items").sole.dig("reconciliation", "checkpoint", "booleans").sole
    expect(value).to eq("name" => "httpd_can_network_connect", "value" => nil)
  end

  it "reflects delayed transition delivery without backfilling the later checkpoint" do
    checkpoint(0, true)
    window = avc(3, 11, checkpoint_at: 0)
    expect(window.host_snapshot).to be_present
    checkpoint(4, false)
    transition = administrative(2, 10)
    item = page(event_id: transition.id).fetch("items").sole
    expect(item["window_avc_count"]).to eq(1)
    expect(item.dig("reconciliation", "status")).to eq("reconciled")
    expect(window.reload.host_snapshot).to be_nil
  end

  it "uses serial ties and treats a checkpoint-time AVC as unresolved" do
    administrative(2, 10)
    avc(2, 9)
    avc(2, 11)
    checkpoint(4, false)
    avc(4, 12, checkpoint_at: 4)
    expect(page.fetch("items").sole["window_avc_count"]).to eq(2)
  end

  it "preserves subsecond checkpoint and transition precision in both projection and interval links" do
    checkpoint(Rational(43831, 1_000_000), true)
    transition = administrative(Rational(2569, 1000), 10)
    window = avc(Rational(2616, 1000), 11)
    checkpoint(4 + Rational(43831, 1_000_000), false)
    administrative(5 + Rational(674, 1000), 12, changes: [["httpd_can_network_connect", false, true]])
    get "/api/v1/hosts/#{host.id}/selinux-activity/#{transition.id}"
    item = JSON.parse(response.body).fetch("item")
    expect(item["event_time"]).to eq((base + Rational(2569, 1000)).iso8601(6))
    expect(item.dig("previous_checkpoint", "event_time")).to eq((base + Rational(43831, 1_000_000)).iso8601(6))
    expect(item.dig("reconciliation", "checkpoint", "event_time")).to eq((base + 4 + Rational(43831, 1_000_000)).iso8601(6))
    expect(item.dig("reconciliation", "next_transition", "event_time")).to eq((base + 5 + Rational(674, 1000)).iso8601(6))
    expect(item["window_occurrences"].map { |occurrence| occurrence["id"] }).to eq([window.id])
  end

  it "does not correlate checkpoints or AVCs across boots with identical audit identities" do
    old = administrative(2, 10, boot: "old-boot")
    checkpoint(4, false, boot: "old-boot")
    avc(3, 11, boot: "old-boot")
    current = administrative(2, 10, boot: "new-boot")
    items = page.fetch("items").index_by { |item| item["id"] }
    expect(items[old.id].dig("reconciliation", "status")).to eq("reconciled")
    expect(items[current.id].dig("reconciliation", "status")).to eq("pending")
    expect(items[current.id]["window_avc_count"]).to eq(0)
    expect(items[current.id]["previous_checkpoint"]).to be_nil
  end

  it "uses retained references inside coalesced observations and handles superseding transitions without double-counting" do
    checkpoint(0, true)
    first = administrative(2, 10)
    avc(2.01, 11)
    second = administrative(2.02, 12, changes: [["httpd_can_network_connect", false, true]])
    avc(3, 13)
    checkpoint(4, true)
    avc(5, 14, checkpoint_at: 4)
    checkpoint(10, true)
    expect(HostSnapshotObservation.count).to eq(1)
    items = page.fetch("items").index_by { |item| item["id"] }
    expect(items[first.id].dig("reconciliation", "status")).to eq("superseded")
    expect(items[first.id].dig("reconciliation", "next_transition", "id")).to eq(second.id)
    expect(items[first.id]["window_avc_count"]).to eq(1)
    expect(items[second.id]["window_avc_count"]).to eq(1)
    expect(Time.iso8601(items[second.id].dig("reconciliation", "checkpoint", "event_time"))).to eq(base + 4)
  end

  it "retains a post-event checkpoint reference from delayed administrative assembly inside a coalesced observation" do
    checkpoint(0, true)
    checkpoint(4, true)
    transition = ingest(2, 10, "boot-1", [[1403, "MAC_POLICY_LOAD", "res=1"]], "selinux_administrative", 4)
    checkpoint(10, true)
    avc(3, 11)
    avc(8, 12)
    item = page(event_id: transition.id).fetch("items").sole
    expect(Time.iso8601(item.dig("reconciliation", "checkpoint", "event_time"))).to eq(base + 4)
    expect(item["window_avc_count"]).to eq(1)
  end

  it "bounds cursor pages and batches actor evidence without returning raw records in the list" do
    21.times { |index| administrative(index, index + 1) }
    queries = []
    subscription = ActiveSupport::Notifications.subscribe("sql.active_record") { |event| queries << event.payload[:sql] }
    first = page
    ActiveSupport::Notifications.unsubscribe(subscription)
    expect(first["items"].size).to eq(20)
    expect(first["coverage"]).to include("Absence of an event does not prove that no change occurred")
    expect(queries.grep(/SELECT "raw_audit_records"/).size).to eq(1)
    expect(first["items"]).to all(satisfy { |item| !item.key?("evidence") && item.dig("actor", "login_uid") == 0 })
    expect(first.dig("meta", "total")).to eq(21)
    older = page(before: first.dig("meta", "next_cursor"))
    expect(older["items"].size).to eq(1)
    expect(older.dig("meta", "next_cursor")).to be_nil
    expect(older.dig("meta", "total")).to eq(21)
    expect((first["items"] + older["items"]).map { |item| item["id"] }.uniq.size).to eq(21)
    numbered = page(page: 1)
    expect(numbered["meta"]).to include("page" => 1, "page_size" => 10, "total" => 21, "total_pages" => 3, "next_cursor" => nil)
    expect(numbered["items"].size).to eq(10)
    second = page(page: 2)
    last = page(page: 999)
    expect(last["meta"]).to include("page" => 3, "total" => 21)
    expect(last["items"].size).to eq(1)
    expect((numbered["items"] + second["items"] + last["items"]).map { |item| item["id"] }).to eq((first["items"] + older["items"]).map { |item| item["id"] })
  end

  it "handles empty numbered pages and rejects invalid pages or mixed selectors" do
    expect(page(page: 3)["meta"]).to include("page" => 1, "page_size" => 10, "total" => 0, "total_pages" => 0)
    [{ page: 0 }, { page: "" }, { page: "1.5" }, { page: 1, before: "cursor" }, { page: 1, event_id: 1 }, { page: 1, occurrence_id: 1 }].each do |params|
      get "/api/v1/hosts/#{host.id}/selinux-activity", params: params
      expect(response).to have_http_status(:unprocessable_content)
    end
  end

  it "rejects invalid cursors and scopes evidence and occurrence selection to the requested host" do
    event = administrative(2, 10)
    get "/api/v1/hosts/#{host.id}/selinux-activity", params: { before: "invalid" }
    expect(response).to have_http_status(:unprocessable_content)
    other = Host.create!(organization: organization, external_id: "other")
    get "/api/v1/hosts/#{other.id}/selinux-activity/#{event.id}"
    expect(response).to have_http_status(:not_found)
    occurrence = avc(3, 11)
    get "/api/v1/hosts/#{other.id}/selinux-activity", params: { occurrence_id: occurrence.id }
    expect(response).to have_http_status(:not_found)
    sign_out_operator
    get "/api/v1/hosts/#{host.id}/selinux-activity"
    expect(response).to have_http_status(:unauthorized)
  end

  def page(**params)
    get "/api/v1/hosts/#{host.id}/selinux-activity", params: params
    expect(response).to have_http_status(:ok)
    JSON.parse(response.body)
  end

  def identity(value)
    "sha256:" + (value ? "a" : "b") * 64
  end

  def checkpoint(offset, value, boot: "boot-1", booleans: nil)
    Heartbeat.call(organization: organization, payload: { "schema_version" => 2, "agent" => { "version" => "test" },
      "host_observed_at" => (base + offset).iso8601(6), "host" => { "id" => "activity-host", "boot_id" => boot,
        "selinux" => { "enforcement" => "enforcing", "policy_identity" => identity(value),
          "booleans" => booleans || [{ "name" => "httpd_can_network_connect", "current" => value, "status" => "observed" }] } } })
  end

  def administrative(offset, sequence, type: "boolean_change", success: true, boot: "boot-1", changes: [["httpd_can_network_connect", true, false]])
    records = if type == "policy_load"
      [[1403, "MAC_POLICY_LOAD", "auid=0 ses=535 res=#{success ? 1 : 0}"]]
    else
      changes.map { |name, old, value| [1405, "MAC_CONFIG_CHANGE", "bool=#{name} val=#{value ? 1 : 0} old_val=#{old ? 1 : 0} auid=0 ses=535#{success ? '' : ' res=0'}"] }
    end
    records += [[1300, "SYSCALL", 'auid=0 uid=0 pid=1402 subj=system_u:system_r:sysadm_t:s0 ses=535 success=yes comm="setsebool" exe="/usr/sbin/setsebool"'],
      [1327, "PROCTITLE", "proctitle=#{'setsebool\0httpd_can_network_connect\0off'.gsub('\\0', "\0").unpack1('H*')}"], [1320, "EOE", ""]]
    ingest(offset, sequence, boot, records, "selinux_administrative")
  end

  def avc(offset, sequence, checkpoint_at: nil, boot: "boot-1")
    raw = ingest(offset, sequence, boot, [[1400, "AVC", 'avc: denied { name_connect } for dest=12345 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:unreserved_port_t:s0 tclass=tcp_socket permissive=0']], "avc", checkpoint_at)
    ProcessRawEvent.call(raw)
    raw.occurrences.sole
  end

  def ingest(offset, sequence, boot, records, category, checkpoint_at = nil)
    time = (base + offset).iso8601(6)
    payload = { "schema_version" => 4, "agent" => { "version" => "test" }, "host_id" => "activity-host", "boot_id" => boot,
      "events" => [{ "category" => category, "audit_event" => { "timestamp" => time, "sequence" => sequence },
        "agent_received_at" => time, "completion_reason" => "eoe", "records" => records.each_with_index.map do |(code, name, fields), position|
          { "position" => position, "type" => code, "type_name" => name, "timestamp" => time, "sequence" => sequence,
            "payload" => Base64.strict_encode64("audit(#{(base + offset).to_f}:#{sequence}): #{fields}") }
        end }] }
    payload["host_observed_at"] = (base + checkpoint_at).iso8601(6) if checkpoint_at
    IngestEvents.new(organization: organization, payload: payload).call.sole
  end
end
