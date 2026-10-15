require "rails_helper"

RSpec.describe "Operator numbered pagination", type: :request do
  around do |example|
    ActiveRecord::Base.transaction do
      example.run
      raise ActiveRecord::Rollback
    end
  end

  before do
    @organization = Organization.create!(name: "pagination")
    @host = @organization.hosts.create!(external_id: "pagination-host", hostname: "000-first")
    @issue = create_issue(0)
    sign_in_operator
  end

  def create_issue(index)
    Issue.create!(organization: @organization, fingerprint_version: 3, fingerprint_digest: "pagination-#{index}",
      source_type: "httpd_t", target_type: "default_t", target_class: "file", permissions: ["read"],
      first_seen_at: Time.utc(2026, 1, 1), last_seen_at: Time.utc(2026, 1, 1))
  end

  def body_for(path, **params)
    get path, params: params
    expect(response).to have_http_status(:ok), response.body
    JSON.parse(response.body)
  end

  it "defaults full-page lists to 25 and honors resized offsets and totals" do
    25.times do |index|
      @organization.hosts.create!(external_id: "pagination-host-#{index}", hostname: "host-#{index.to_s.rjust(3, '0')}")
      create_issue(index + 1)
    end
    [["/api/v1/hosts", "hosts"], ["/api/v1/issues", "issues"]].each do |path, key|
      first = body_for(path)
      expect(first.fetch(key).size).to eq(25)
      expect(first["meta"]).to include("page_size" => 25, "total" => 26, "total_pages" => 2)
      second = body_for(path, limit: 10, page: 2)
      expect(second.fetch(key).map { |item| item["id"] }).to eq(first.fetch(key).drop(10).first(10).map { |item| item["id"] })
      expect(second["meta"]).to include("page_size" => 10, "page" => 2, "total_pages" => 3)
      large = body_for(path, limit: 100)
      expect(large.fetch(key).size).to eq(26)
      expect(large.dig("meta", "page_size")).to eq(100)
    end
    expect(body_for("/api/v1/hosts", host_id: @host.id, limit: 100).dig("meta", "total")).to eq(1)
    expect(body_for("/api/v1/issues", source_type: "other_t", limit: 100).dig("meta", "total")).to eq(0)
  end

  it "applies full-page defaults to host inventories and numbered global log" do
    path = "/api/v1/hosts/#{@host.id}/configuration"
    expect(body_for(path, view: "booleans").dig("booleans", "page_size")).to eq(25)
    expect(body_for(path, view: "ports", limit: 100).dig("ports", "page_size")).to eq(100)
    expect(body_for("/api/v1/selinux-log", page: 1).dig("meta", "page_size")).to eq(25)
    expect(body_for("/api/v1/selinux-log", page: 1, limit: 100).dig("meta", "page_size")).to eq(100)
    expect(body_for("/api/v1/selinux-log").dig("meta", "page_size")).to eq(50)
  end

  it "uses embedded defaults and leaves cursor interfaces intact" do
    host_path = "/api/v1/hosts/#{@host.id}"
    [["#{host_path}/occurrences", {}], ["#{host_path}/selinux-activity", {}], ["/api/v1/issues/#{@issue.id}/occurrences", { view: "summary" }]].each do |path, params|
      expect(body_for(path, **params, page: 1).dig("meta", "page_size")).to eq(10)
      [25, 50].each { |size| expect(body_for(path, **params, page: 1, limit: size).dig("meta", "page_size")).to eq(size) }
    end
    expect(body_for("#{host_path}/selinux-activity").dig("meta", "page_size")).to eq(20)
    expect(body_for("#{host_path}/occurrences")["meta"]).not_to have_key("page_size")
  end

  it "rejects malformed and out-of-bounds sizes at every numbered boundary" do
    full = [["/api/v1/hosts", {}], ["/api/v1/issues", {}], ["/api/v1/hosts/#{@host.id}/configuration", { view: "booleans" }], ["/api/v1/selinux-log", { page: 1 }]]
    embedded = [["/api/v1/hosts/#{@host.id}/occurrences", { page: 1 }], ["/api/v1/hosts/#{@host.id}/selinux-activity", { page: 1 }], ["/api/v1/issues/#{@issue.id}/occurrences", { view: "summary", page: 1 }]]
    (full + embedded).each do |path, params|
      [0, "", "1.5", "bad", [25], { value: 25 }, 101].each do |invalid|
        get path, params: params.merge(limit: invalid)
        expect(response).to have_http_status(:unprocessable_content), "#{path}: #{invalid.inspect}: #{response.body}"
      end
    end
    embedded.each do |path, params|
      get path, params: params.merge(limit: 100)
      expect(response).to have_http_status(:unprocessable_content)
    end
  end
end
