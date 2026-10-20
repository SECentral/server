require "rails_helper"
require Rails.root.join("db/migrate/20261020000001_group_issue_signatures")

RSpec.describe GroupIssueSignatures do
  it "consolidates relationships while retaining decisions, intent snapshots and occurrence provenance" do
    connection = ActiveRecord::Base.connection
    schema = "grouping_migration_#{SecureRandom.hex(6)}"
    original_path = connection.schema_search_path
    connection.execute("CREATE SCHEMA #{schema}")
    connection.schema_search_path = schema
    connection.execute("CREATE TABLE issues (LIKE public.issues INCLUDING DEFAULTS)")
    connection.execute("ALTER TABLE issues ADD PRIMARY KEY (id)")
    %w[occurrences issue_disposition_changes resolution_intents resolution_intent_changes].each do |table|
      connection.execute("CREATE TABLE #{table} (id bigint PRIMARY KEY, issue_id bigint REFERENCES issues(id), retained text)")
    end
    connection.execute("CREATE UNIQUE INDEX index_resolution_intents_on_issue_id ON resolution_intents(issue_id)")
    connection.execute("CREATE TABLE policy_draft_entries (id bigint PRIMARY KEY, provenance jsonb NOT NULL)")
    connection.execute(%q{INSERT INTO policy_draft_entries VALUES (1, '[{"issue_id":2,"occurrence_id":2,"retained":"original"}]')})
    %w[read open map].each_with_index do |permission, index|
      id = index + 1
      status = %w[ignored resolved open][index]
      disposition = %w[expected_harmless labeling_configuration unclassified][index]
      connection.execute(<<~SQL)
        INSERT INTO issues (id, organization_id, source_type, target_type, target_class, fingerprint_version,
          fingerprint_digest, permissions, status, disposition, first_seen_at, last_seen_at, created_at, updated_at)
        VALUES (#{id}, 1, 'httpd_t', 'user_home_t', 'file', 3, 'old-#{id}', '["#{permission}"]', '#{status}', '#{disposition}', NOW(), NOW(), NOW(), NOW())
      SQL
      %w[occurrences issue_disposition_changes resolution_intents resolution_intent_changes].each do |table|
        connection.execute("INSERT INTO #{table} VALUES (#{id}, #{id}, 'original-#{id}')")
      end
    end

    described_class.new.migrate(:up)

    parent = connection.select_one("SELECT * FROM issues")
    expect(connection.select_value("SELECT COUNT(*) FROM issues")).to eq(1)
    expect(parent).to include("fingerprint_version" => 4, "status" => "open", "disposition" => "mixed", "occurrences_count" => 3)
    expect(JSON.parse(parent.fetch("permissions"))).to eq(%w[map open read])
    expect(connection.select_values("SELECT status FROM issue_signatures ORDER BY id")).to eq(%w[ignored resolved open])
    expect(connection.select_values("SELECT fingerprint_digest FROM issue_signatures ORDER BY id")).to eq(%w[old-1 old-2 old-3])
    provenance = JSON.parse(connection.select_value("SELECT provenance FROM policy_draft_entries"))
    expect(provenance).to eq([{ "issue_id" => 1, "issue_signature_id" => 2, "occurrence_id" => 2, "retained" => "original" }])
    %w[occurrences issue_disposition_changes resolution_intents resolution_intent_changes].each do |table|
      expect(connection.select_values("SELECT issue_id FROM #{table}")).to eq([1, 1, 1])
      expect(connection.select_values("SELECT issue_signature_id FROM #{table} ORDER BY id")).to eq([1, 2, 3])
      expect(connection.select_values("SELECT retained FROM #{table} ORDER BY id")).to eq(%w[original-1 original-2 original-3])
    end
  ensure
    connection.schema_search_path = original_path if original_path
    connection.execute("DROP SCHEMA IF EXISTS #{schema} CASCADE") if schema
    connection.schema_cache.clear!
  end
end
