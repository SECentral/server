require "rails_helper"
require_relative "../support/port_resolution_fixtures"

RSpec.describe PortMappingGuidance do
  include PortResolutionFixtures
  around do |example|
    ActiveRecord::Base.transaction do
      example.run
      raise ActiveRecord::Rollback
    end
  end

  def result(issue)
    described_class.new(issue, occurrences: issue.occurrences.includes(:host, :normalized_denial).order(occurred_at: :desc, id: :desc)).call
  end

  it "supports a Scenario 003 single-port add inside a generic base range using exact bind evidence" do
    issue, occurrence, host, = port_fixture
    data = result(issue)
    proposal = data[:proposals].sole
    expect(data[:investigations].sole).to include(protocol: "tcp", port: 12345, operation: "name_bind", host_id: host.id, occurrence_id: occurrence.id)
    expect(proposal[:basis]).to include(action: "add", target_port_type: "http_port_t")
    expect(proposal[:plan][:apply_steps].sole[:command]).to eq("sudo semanage port -a -p tcp -t http_port_t 12345")
    expect(proposal[:plan][:rollback_steps].sole[:command]).to eq("sudo semanage port -d -p tcp 12345")
    expect(proposal[:candidate][:expected_effect]).to include("other workloads", "opens no firewall")
  end

  it "counts all retained endpoint occurrences separately for each host without changing proposal semantics" do
    issue, occurrence, host, = port_fixture
    original = result(issue)[:proposals].sole
    raw = occurrence.raw_event.dup
    raw.audit_sequence += 1
    raw.save!
    denial = occurrence.normalized_denial.dup
    denial.raw_event = raw
    denial.save!
    repeated = occurrence.dup
    repeated.raw_event = raw
    repeated.normalized_denial = denial
    repeated.occurred_at += 1.second
    repeated.save!
    _issue, _other_occurrence, other_host, = port_fixture(issue: issue)

    data = result(issue)
    expect(data[:investigations].to_h { |item| [item[:host_id], item[:occurrence_count]] }).to eq(host.id => 2, other_host.id => 1)
    expect(data[:proposals].find { |item| item[:basis][:host_id] == host.id }.slice(:semantic_basis, :plan)).to eq(original.slice(:semantic_basis, :plan))
  end

  it "keeps UDP bind and TCP connect distinct and never uses connect evidence as a local bind" do
    bind, = port_fixture(protocol: "udp")
    expect(result(bind)[:proposals].sole[:plan][:apply_steps].sole[:command]).to include("-p udp")
    connect, = port_fixture(operation: "name_connect")
    expect(result(connect)[:investigations].sole).to include(operation: "name_connect", port: 12345)
    expect(result(connect)[:proposals].sole[:plan][:preview_steps].last[:command]).to eq("ss -tnp")
    expect(result(connect)[:proposals].sole[:plan][:verification_steps].sole[:explanation]).to include("outbound request through the confined workload")
  end

  it "modifies an existing local generic singleton and rolls back by modification, not deletion" do
    issue, = port_fixture(mappings: [port_range("unreserved_port_t", 12345, provenance: "custom")])
    proposal = result(issue)[:proposals].sole
    expect(proposal[:plan][:apply_steps].sole[:command]).to include("port -m")
    expect(proposal[:plan][:rollback_steps].sole[:command]).to eq("sudo semanage port -m -p tcp -t unreserved_port_t 12345")
    expect(proposal[:plan][:rollback_description]).to include("do not delete")
  end

  it "removes only a new local override when modifying an exact generic base record" do
    issue, = port_fixture(mappings: [port_range("unreserved_port_t", 12345)])
    proposal = result(issue)[:proposals].sole
    expect(proposal[:plan][:apply_steps].sole[:command]).to include("port -m")
    expect(proposal[:plan][:rollback_steps].sole[:command]).to eq("sudo semanage port -d -p tcp 12345")
    expect(proposal[:plan][:rollback_description]).to include("new singleton local record/override")
  end

  it "treats an equivalent service mapping as a no-op without commands" do
    issue, = port_fixture(mappings: [port_range("unreserved_port_t", 1024, 32767), port_range("http_port_t", 12345)])
    data = result(issue)
    expect(data[:proposals]).to be_empty
    expect(data[:investigations].sole).to include(state: "no_change")
    expect(data[:investigations].sole[:types].sole).to include(state: "no_op")
  end

  it "blocks service-specific classifications, custom ranges, conflicting overlaps and unknown provenance" do
    cases = [
      [[port_range("ssh_port_t", 12345)], "service-specific"],
      [[port_range("unreserved_port_t", 12340, 12350, provenance: "custom")], "local range"],
      [[port_range("unreserved_port_t", 1024, 32767), port_range("reserved_port_t", 12340, 12350)], "conflicting generic"],
      [[port_range("unreserved_port_t", 1024, 32767, provenance: "unknown")], "provenance is unknown"]
    ]
    cases.each do |mappings, reason|
      ActiveRecord::Base.transaction(requires_new: true) do
        issue, = port_fixture(mappings: mappings)
        data = result(issue)
        expect(data[:proposals]).to be_empty
        expect(data[:investigations].sole[:reason]).to include(reason)
        raise ActiveRecord::Rollback
      end
    end
  end

  it "does not confuse partial or missing local inventory with an absent mapping" do
    issue, _, host, snapshot, = port_fixture
    replace_port_snapshot(host, snapshot, "selinux" => { "policy" => { "port_inventory" => { "local_classification_status" => "unavailable" } } })
    data = result(issue)
    expect(data[:proposals]).to be_empty
    expect(data[:investigations].sole[:reason]).to include("local override classification is unavailable", "semanage port -l -C")
  end

  it "keeps stale evidence ineligible and exposes a specific refresh step" do
    issue, _, host, = port_fixture
    host.host_snapshot_observations.first.update!(last_received_at: 1.hour.ago)
    proposal = result(issue)[:proposals].sole
    expect(proposal[:candidate]).to include(status: "evidence_changed")
    expect(proposal[:candidate][:unavailable_reason]).to include("stale")
  end

  it "preserves pending/failed evaluation instead of guessing a type from a service or catalog" do
    issue, _, _, _, fact = port_fixture
    %w[pending error unavailable].each do |status|
      fact.update!(status: status)
      data = result(issue)
      expect(data[:proposals]).to be_empty
      expect(data[:investigations].sole[:reason]).to include(status)
    end
  end

  it "evaluates target-attribute alternatives and relevant Boolean state without generating compound changes" do
    issue, _, host, snapshot, fact = port_fixture
    rule = "allow httpd_t web_ports:tcp_socket name_bind; [ feature_enabled ]:True"
    fact.update!(matching_rules: [rule], rule_details: [{ "rule" => rule, "target_types" => %w[http_port_t http_cache_port_t], "conditional_expression" => "feature_enabled" }, fact.rule_details.last])
    expect(result(issue)[:proposals]).to be_empty
    expect(result(issue)[:investigations].sole).to include(state: "blocked")
    expect(result(issue)[:investigations].sole[:types].map { |type| type[:state] }).to eq(%w[conditional conditional])
    replace_port_snapshot(host, snapshot, "selinux" => { "booleans" => [{ "name" => "feature_enabled", "status" => "observed", "current" => true }] })
    expect(result(issue)[:proposals].map { |proposal| proposal[:basis][:target_port_type] }).to contain_exactly("http_port_t", "http_cache_port_t")
  end

  it "prioritizes retry when current conditional connect policy already supports the observed port type" do
    issue, _, host, snapshot, fact = port_fixture(operation: "name_connect")
    rule = "allow httpd_t port_type:tcp_socket name_connect; [ httpd_can_network_connect ]:True"
    fact.update!(matching_rules: [rule], rule_details: [{ "rule" => rule, "target_types" => %w[http_port_t unreserved_port_t], "conditional_expression" => "httpd_can_network_connect" }, fact.rule_details.last])
    replace_port_snapshot(host, snapshot, "selinux" => { "booleans" => [{ "name" => "httpd_can_network_connect", "status" => "observed", "current" => true }] })
    data = result(issue)
    expect(data[:proposals]).to be_empty
    expect(data[:investigations].sole[:reason]).to include("already supplies name_connect", "retry the intended workload")
  end

  it "does not borrow another host's inventory, identity, port or applicable permission" do
    issue, first, = port_fixture
    _, second, host, snapshot, fact = port_fixture(issue: issue, port: 12346)
    fact.update!(permission: "name_connect")
    replace_port_snapshot(host, snapshot, "selinux" => { "policy" => { "port_inventory" => { "status" => "partial" } } })
    data = result(issue)
    expect(data[:proposals].map { |proposal| proposal[:occurrence_id] }).to eq([first.id])
    expect(data[:investigations].find { |item| item[:occurrence_id] == second.id }[:reason]).to include("partial")
  end

  it "does not invent an endpoint from ambiguous/zero bind ports, destination fields or mixed permissions" do
    issue, occurrence, = port_fixture
    [[], ["0"], ["12345", "12346"], ["12345;id"]].each do |ports|
      occurrence.normalized_denial.update!(details: { "network_evidence" => { "bind_port_fields" => ports, "dest_fields" => ["80"] } })
      data = result(issue)
      expect(data[:proposals]).to be_empty
      expect(data[:investigations].sole).to include(port: nil)
    end
    occurrence.normalized_denial.update!(permissions: %w[name_bind name_connect])
    expect(result(issue)[:investigations]).to be_empty
  end

  it "honors a known port-write boundary rather than reusing the last stored inventory or policy" do
    issue, occurrence, = port_fixture
    boundary = occurrence.raw_event.dup
    boundary.assign_attributes(category: "selinux_administrative", transition_type: "port_change", audit_sequence: 2, audit_timestamp: Time.current)
    boundary.save!
    data = result(issue)
    expect(data[:proposals]).to be_empty
    expect(data[:investigations].sole[:reason]).to include("policy identity is missing or invalidated")
  end

  it "uses exact policy record boundaries rather than coalesced inventory to choose modify" do
    issue, _, _, _, fact = port_fixture
    records = fact.rule_details.last.deep_dup
    records["mappings"] << { "type" => "unreserved_port_t", "start" => 12345, "end" => 12345 }
    fact.update!(rule_details: [fact.rule_details.first, records])
    expect(result(issue)[:proposals].sole[:plan][:apply_steps].sole[:command]).to include("port -m")
  end

  it "blocks missing or conflicting exact-policy record evidence" do
    issue, _, _, _, fact = port_fixture
    rule = fact.rule_details.first
    fact.update!(rule_details: [rule])
    expect(result(issue)[:investigations].sole[:reason]).to include("record boundaries are missing")
    fact.update!(rule_details: [rule, { "kind" => "port_contexts", "protocol" => "tcp", "mappings" => [{ "type" => "ssh_port_t", "start" => 12345, "end" => 12345 }] }])
    expect(result(issue)[:proposals]).to be_empty
    expect(result(issue)[:investigations].sole[:reason]).to include("inventory conflict")
  end

  it "requires an observed current boot identity rather than treating missing identity as stable" do
    issue, _, host, snapshot, = port_fixture
    replace_port_snapshot(host, snapshot, "boot_id" => nil)
    data = result(issue)
    expect(data[:proposals]).to be_empty
    expect(data[:investigations].sole[:reason]).to include("boot identity is missing")
  end

  it "exposes every exact-policy possibility and eligible proposal beyond the old display limit" do
    issue, _, _, _, fact = port_fixture
    types = %w[http_port_t http_cache_port_t] + 20.times.map { |index| "other_service_#{index}_port_t" }
    rule = "allow httpd_t test_ports:tcp_socket name_bind;"
    fact.update!(matching_rules: [rule], rule_details: [{ "rule" => rule, "target_types" => types }, fact.rule_details.last])
    data = result(issue)
    expect(data[:investigations].sole[:type_count]).to eq(types.size)
    expect(data[:investigations].sole[:types].map { |option| option[:type] }).to match_array(types)
    expect(data[:proposals].map { |proposal| proposal[:basis][:target_port_type] }).to match_array(types)
  end

  it "uses explicit sourced descriptions only for discovered types, never type-name similarity or process identity" do
    issue, _, _, _, fact = port_fixture
    rule = "allow httpd_t test_ports:tcp_socket name_bind;"
    fact.update!(matching_rules: [rule], rule_details: [{ "rule" => rule, "target_types" => %w[http_port_t http_unlisted_port_t] }, fact.rule_details.last])
    options = result(issue)[:investigations].sole[:types].index_by { |option| option[:type] }
    expect(options["http_port_t"][:service]).to include(id: "http", label: "HTTP service", source_entry: "network_port(http, ...) declares http_port_t")
    expect(options["http_port_t"][:service][:source_url]).to include("fedora-selinux/selinux-policy/blob/5cac04d24778cfec5f6aee261aac01be0f9e1de4")
    expect(options["http_unlisted_port_t"]).not_to have_key(:service)
    expect(options).not_to have_key("http_cache_port_t")
  end
end
