require "rails_helper"

RSpec.describe "Global SELinux log", type: :request do
  let(:organization) { Organization.create!(name: "log") }
  let(:host) { organization.hosts.create!(external_id: "log-host", hostname: "web-1") }
  let(:agent) { organization.agent_installations.create!(name: "collector", bound_host: host) }
  let(:time) { Time.iso8601("2026-10-13T12:00:00.123456Z") }

  around do |example|
    ActiveRecord::Base.transaction do
      example.run
      raise ActiveRecord::Rollback
    end
  end

  before { sign_in_operator }

  def event(category: "avc", at: time, **attrs)
    RawEvent.create!({ organization: organization, host: host, agent_installation: agent,
      category: category, audit_timestamp: at, audit_sequence: RawEvent.count + 1,
      boot_id: "boot", completion_reason: "eoe", evidence_digest: "a" * 64,
      agent_received_at: at + 10, server_received_at: at + 20, schema_version: 4 }.merge(attrs))
  end

  def occurrence(raw = event, ordinal: 0)
    denial = raw.normalized_denials.create!(normalization_version: 1, ordinal: ordinal, status: "ungroupable",
      source_type: "httpd_t", target_type: "var_t", target_class: "file", permissions: ["read"],
      target_paths: ["/srv/data"], command: "httpd", details: { permissive: true })
    Occurrence.create!(organization: raw.organization, host: raw.host, raw_event: raw,
      normalized_denial: denial, occurred_at: raw.audit_timestamp)
  end

  def log(**params)
    organization
    get "/api/v1/selinux-log", params: params
    JSON.parse(response.body)
  end

  it "orders mixed hosts and categories by canonical microsecond event time, not receipt or occurrence time" do
    older = occurrence(event(at: time - Rational(1, 1_000_000)))
    tied = occurrence
    tied.update!(occurred_at: time + 1.day)
    admin = event(category: "selinux_administrative", transition_type: "policy_load")
    other = organization.hosts.create!(external_id: "old-host", hostname: "offline")
    newer = occurrence(event(at: time + Rational(1, 1_000_000), host: other))
    event # A raw AVC without an occurrence is not listed.
    data = log
    expect(response).to have_http_status(:ok)
    expect(data["items"].map { |item| [item["category"], item["id"]] }).to eq([
      ["avc", newer.id], ["administrative", admin.id], ["avc", tied.id], ["avc", older.id]
    ])
    expect(data["items"][2]).to include("event_time" => time.iso8601(6), "issue_id" => nil)
    expect(data["items"][0].dig("host", "hostname")).to eq("offline")
    expect(data["items"][1]["administrative"]).not_to have_key("reconciliation")
    expect(data["coverage"]).to include("Raw AVCs without occurrences are not listed")
    expect(log(category: "administrative")["items"].map { |item| item["id"] }).to eq([admin.id])
    expect(log(category: "avc", host_id: other.id)["items"].map { |item| item["id"] }).to eq([newer.id])
    expect(log(start: time.iso8601(6), end: (time + Rational(1, 1_000_000)).iso8601(6))["items"].size).to eq(2)
  end

  it "paginates tied source IDs and multiple occurrences without loss or duplicates" do
    raw = event
    occurrences = [occurrence(raw), occurrence(raw, ordinal: 1)]
    admin = event(category: "selinux_administrative", transition_type: "policy_load")
    seen = []
    cursor = nil
    loop do
      params = { limit: 1 }
      params[:before] = cursor if cursor
      data = log(**params)
      expect(response).to have_http_status(:ok)
      seen.concat(data["items"].map { |item| [item["category"], item["id"]] })
      cursor = data.dig("meta", "next_cursor")
      break unless cursor
    end
    expect(seen).to eq([["administrative", admin.id]] + occurrences.reverse.map { |item| ["avc", item.id] })
  end

  it "rejects changed cursor filters and signatures but allows changing page size" do
    3.times { occurrence }
    cursor = log(limit: 1).dig("meta", "next_cursor")
    [ { category: "avc" }, { host_id: host.id }, { start: (time - 1).iso8601(6) }, { end: (time + 1).iso8601(6) } ].each do |filters|
      log(before: cursor, **filters)
      expect(response).to have_http_status(:unprocessable_content)
    end
    log(before: cursor + "modified")
    expect(response).to have_http_status(:unprocessable_content)
    expect(log(before: cursor, limit: 2)["items"].size).to eq(2)
    expect(response).to have_http_status(:ok)
    bad_version = Rails.application.message_verifier("selinux-log-cursor").generate({ "version" => 2 })
    log(before: bad_version)
    expect(response).to have_http_status(:unprocessable_content)
  end

  it "supports numbered mixed-category pages, filtered totals, page size changes and out-of-range clamping" do
    raw = event
    13.times { |index| occurrence(raw, ordinal: index) }
    2.times { event(category: "selinux_administrative", transition_type: "policy_load") }
    expected = log["items"].map { |item| [item["category"], item["id"]] }
    pages = (1..3).map do |page|
      data = log(page: page, limit: 5)
      expect(response).to have_http_status(:ok)
      expect(data["meta"]).to include("page" => page, "page_size" => 5, "total" => 15, "total_pages" => 3, "next_cursor" => nil)
      data["items"].map { |item| [item["category"], item["id"]] }
    end
    expect(pages.flatten(1)).to eq(expected)
    expect(log(page: 99, limit: 5)["meta"]["page"]).to eq(3)
    expect(log(page: 1, limit: 25)["items"].size).to eq(15)
    expect(log(page: 1, category: "administrative")["meta"]).to include("total" => 2, "total_pages" => 1)
    expect(log(page: 1, start: (time + 1).iso8601(6))["meta"]).to include("page" => 1, "total" => 0, "total_pages" => 0)
    [{ page: 0 }, { page: "1x" }, { page: [1] }, { page: 1, before: "cursor" }].each do |params|
      log(**params)
      expect(response).to have_http_status(:unprocessable_content)
    end
  end

  it "filters both branches by multiple hosts and binds cursors to the normalized host set" do
    first = occurrence
    other = organization.hosts.create!(external_id: "second", hostname: "db-1")
    second = occurrence(event(host: other))
    admin = event(category: "selinux_administrative", transition_type: "policy_load", host: other)
    excluded = organization.hosts.create!(external_id: "excluded")
    occurrence(event(host: excluded))
    event(category: "selinux_administrative", transition_type: "policy_load", host: excluded)
    ids = [host.id, other.id]
    data = log(host_ids: ids, page: 1)
    expect(response).to have_http_status(:ok)
    expect(data["meta"]["total"]).to eq(3)
    expect(data["items"].map { |item| [item["category"], item["id"]] }).to eq([["administrative", admin.id], ["avc", second.id], ["avc", first.id]])
    expect(log(host_ids: ids, category: "avc", page: 1)["meta"]["total"]).to eq(2)
    expect(log(host_ids: ids, category: "administrative", page: 1)["meta"]["total"]).to eq(1)
    cursor = log(host_ids: ids, limit: 1).dig("meta", "next_cursor")
    expect(log(host_ids: ids.reverse + ids, before: cursor)["items"].size).to eq(2)
    expect(response).to have_http_status(:ok)
    log(host_ids: [host.id], before: cursor)
    expect(response).to have_http_status(:unprocessable_content)
    get "/api/v1/selinux-log/hosts", params: { host_ids: ids }
    expect(JSON.parse(response.body)["hosts"].map { |item| item["id"] }).to match_array(ids)
  end

  it "validates multi-host selections and preserves legacy single-host cursor compatibility" do
    2.times { occurrence }
    cursor = log(host_id: host.id, limit: 1).dig("meta", "next_cursor")
    expect(log(host_ids: [host.id], before: cursor)["items"].size).to eq(1)
    expect(response).to have_http_status(:ok)
    [{ host_ids: "1" }, { host_ids: ["1x"] }, { host_ids: [0] }, { host_ids: Array.new(51, host.id) },
      { host_id: host.id, host_ids: [host.id] }, { host_ids: [{ id: host.id }] }].each do |params|
      log(**params)
      expect(response).to have_http_status(:unprocessable_content), params.inspect
      get "/api/v1/selinux-log/hosts", params: params
      expect(response).to have_http_status(:unprocessable_content), params.inspect
    end
    log(host_ids: [host.id, 9_999_999])
    expect(response).to have_http_status(:not_found)
  end

  it "validates limits, categories, dates, precision and interval order" do
    [ { limit: 0 }, { limit: 51 }, { limit: "1x" }, { category: "other" }, { host_id: "1x" },
      { start: "2026-02-30T12:00:00Z" }, { start: "2026-10-13T24:00:00Z" },
      { start: "2026-10-13T12:00:00" }, { start: "2026-10-13T12:00:00.1234567Z" },
      { start: "0000-01-01T00:00:00Z" }, { category: ["avc"] }, { host_id: [host.id] },
      { start: time.iso8601(6), end: time.iso8601(6) }, { before: "invalid" } ].each do |filters|
      log(**filters)
      expect(response).to have_http_status(:unprocessable_content), filters.inspect
    end
  end

  it "shares eligibility and evidence summaries for all five administrative types, including reported history" do
    records = [["policy_load", 1403, "res=1"], ["boolean_change", 1405, "bool=httpd_can_network_connect val=1 old_val=0"],
      ["enforcement_change", 1404, "enforcing=0 old_enforcing=1"], ["port_change", 2312, "msg='resrc=port op=modify'"],
      ["file_context_change", 2312, "msg='resrc=fcontext op=modify'"]]
    records.each do |type, code, payload|
      raw = event(category: "selinux_administrative", transition_type: type)
      raw.raw_audit_records.create!(position: 0, record_type: code, type_name: "test", audit_timestamp: time,
        sequence: raw.audit_sequence, payload: payload + ' auid=0 uid=0 comm="semanage"')
    end
    reported = event(category: "selinux_administrative")
    reported.raw_audit_records.create!(position: 0, record_type: 1404, type_name: "MAC_STATUS", audit_timestamp: time,
      sequence: reported.audit_sequence, payload: "enforcing=0")
    event(category: "selinux_administrative") # Unsupported event is excluded.
    items = log(category: "administrative")["items"]
    expect(items.size).to eq(6)
    items.each do |item|
      get "/api/v1/hosts/#{host.id}/selinux-activity", params: { event_id: item["id"] }
      detail = JSON.parse(response.body)["items"].sole
      expect(item["administrative"]).to eq(detail.slice(*item["administrative"].keys))
      expect(item["actor"]).to eq(detail["actor"])
    end
    expect(items.first.dig("administrative", "boundary_established")).to eq(false)
  end

  it "scopes both branches and host search, failing closed for zero or multiple organizations" do
    occurrence
    event(category: "selinux_administrative", transition_type: "policy_load")
    other = Organization.create!(name: "foreign")
    foreign_host = other.hosts.create!(external_id: "foreign")
    foreign_raw = event(category: "selinux_administrative", transition_type: "policy_load", organization: other, host: foreign_host)
    foreign_avc = occurrence(event(organization: other, host: foreign_host))
    foreign_issue = other.issues.create!(fingerprint_version: 3, fingerprint_digest: "foreign", source_type: "httpd_t",
      target_type: "var_t", target_class: "file", permissions: ["read"], first_seen_at: time, last_seen_at: time)
    expect(SelinuxLogQuery.new(organization: organization).call[:items].map { |item| item[:host][:id] }.uniq).to eq([host.id])
    expect { SelinuxLogQuery.new(organization: organization, filters: { "host_id" => foreign_host.id.to_s }) }.to raise_error(ActiveRecord::RecordNotFound)
    expect { SelinuxLogQuery.new(organization: organization, filters: { "host_ids" => [host.id.to_s, foreign_host.id.to_s] }) }.to raise_error(ActiveRecord::RecordNotFound)
    ["/api/v1/selinux-log", "/api/v1/selinux-log/hosts", "/api/v1/hosts/#{foreign_host.id}",
      "/api/v1/hosts/#{foreign_host.id}/occurrences/#{foreign_avc.id}",
      "/api/v1/hosts/#{foreign_host.id}/selinux-activity/#{foreign_raw.id}"].each do |path|
      get path
      expect(response).to have_http_status(:service_unavailable)
    end
    # Query scope is independently exercised even when the deployment invariant fails.
    allow(Organization).to receive(:sole).and_return(organization)
    get "/api/v1/selinux-log/hosts"
    expect(JSON.parse(response.body)["hosts"].map { |item| item["id"] }).to eq([host.id])
    ["/api/v1/hosts/#{foreign_host.id}", "/api/v1/hosts/#{host.id}/occurrences/#{foreign_avc.id}",
      "/api/v1/hosts/#{host.id}/selinux-activity/#{foreign_raw.id}", "/api/v1/issues/#{foreign_issue.id}",
      "/api/v1/issues/#{foreign_issue.id}/occurrences", "/api/v1/issues/#{foreign_issue.id}/analysis",
      "/api/v1/issues/#{foreign_issue.id}/resolutions"].each do |path|
      get path
      expect(response).to have_http_status(:not_found)
    end
    allow(Organization).to receive(:sole).and_raise(ActiveRecord::RecordNotFound)
    get "/api/v1/selinux-log"
    expect(response).to have_http_status(:service_unavailable)
  end

  it "opens an occurrence directly, including an ungrouped occurrence, and rejects host substitution" do
    item = occurrence
    get "/api/v1/hosts/#{host.id}/occurrences/#{item.id}"
    expect(response).to have_http_status(:ok)
    expect(JSON.parse(response.body)).to include("id" => item.id, "issue" => nil)
    other = organization.hosts.create!(external_id: "another")
    get "/api/v1/hosts/#{other.id}/occurrences/#{item.id}"
    expect(response).to have_http_status(:not_found)
  end

  it "returns an associated issue link without computing investigation guidance in the list" do
    item = occurrence
    issue = organization.issues.create!(fingerprint_version: 3, fingerprint_digest: "grouped", source_type: "httpd_t",
      target_type: "var_t", target_class: "file", permissions: ["read"], first_seen_at: time, last_seen_at: time)
    item.update!(issue: issue)
    expect(InvestigationGuidance).not_to receive(:call)
    expect(log["items"].sole["issue_id"]).to eq(issue.id)
  end

  it "searches stored host names/identities literally and validates selected IDs" do
    host.update!(hostname: "web%_one")
    organization.hosts.create!(external_id: "another", hostname: "web-other")
    get "/api/v1/selinux-log/hosts", params: { q: "%_" }
    expect(JSON.parse(response.body)["hosts"].map { |item| item["id"] }).to eq([host.id])
    get "/api/v1/selinux-log/hosts", params: { host_id: "1x" }
    expect(response).to have_http_status(:unprocessable_content)
  end

  it "preserves traversal keys when entries are removed or arrive late" do
    first = occurrence(event(at: time + 3))
    second = occurrence(event(at: time + 2))
    last = occurrence(event(at: time + 1))
    cursor = log(limit: 1).dig("meta", "next_cursor")
    first.delete
    late = occurrence(event(at: time + 4))
    expect(log(before: cursor)["items"].map { |item| item["id"] }).to eq([second.id, last.id])
    expect(log["items"].first["id"]).to eq(late.id)
  end

  it "requires authentication" do
    organization
    sign_out_operator
    get "/api/v1/selinux-log"
    expect(response).to have_http_status(:unauthorized)
  end
end
