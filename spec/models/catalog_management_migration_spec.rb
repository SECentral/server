require "rails_helper"
require Rails.root.join("db/migrate/20261009000001_create_catalog_managements")

RSpec.describe CreateCatalogManagements do
  it "backfills the existing derived names and active state without editing revision/import bytes" do
    connection = ActiveRecord::Base.connection
    schema = "catalog_backfill_#{SecureRandom.hex(6)}"
    original_path = connection.schema_search_path
    connection.execute("CREATE SCHEMA #{schema}")
    connection.schema_search_path = schema
    connection.execute("CREATE TABLE distribution_catalog_revisions (id bigint PRIMARY KEY, distribution varchar NOT NULL, major_version varchar NOT NULL, content_digest varchar NOT NULL, loaded_policy_digest varchar NOT NULL)")
    connection.execute("CREATE TABLE distribution_catalog_imports (id bigint PRIMARY KEY, artifact bytea NOT NULL, acquisition_metadata jsonb NOT NULL)")
    connection.execute("INSERT INTO distribution_catalog_revisions VALUES (1, 'almalinux', '9', 'retained-content-1', 'retained-policy-1'), (2, 'rhel', '9', 'retained-content-2', 'retained-policy-2')")
    connection.execute("INSERT INTO distribution_catalog_imports VALUES (1, decode('00ff0102', 'hex'), '{\"source\":\"retained\"}')")
    before = %w[distribution_catalog_revisions distribution_catalog_imports].map { |table| connection.select_all("SELECT * FROM #{table} ORDER BY id").to_a }

    described_class.new.migrate(:up)

    expect(connection.select_all("SELECT distribution_catalog_revision_id, display_name, lifecycle FROM catalog_managements ORDER BY distribution_catalog_revision_id").to_a).to eq([
      { "distribution_catalog_revision_id" => 1, "display_name" => "AlmaLinux 9", "lifecycle" => "active" },
      { "distribution_catalog_revision_id" => 2, "display_name" => "RHEL 9", "lifecycle" => "active" }
    ])
    after = %w[distribution_catalog_revisions distribution_catalog_imports].map { |table| connection.select_all("SELECT * FROM #{table} ORDER BY id").to_a }
    expect(after).to eq(before)
  ensure
    connection.schema_search_path = original_path if original_path
    connection.execute("DROP SCHEMA IF EXISTS #{schema} CASCADE") if schema
    connection.schema_cache.clear!
  end
end
