require "rails_helper"
require Rails.root.join("db/migrate/20261013000002_add_host_reporting_duration")

RSpec.describe AddHostReportingDuration do
  it "preserves legacy evidence without backfill and enforces duration and identity constraints" do
    connection = ActiveRecord::Base.connection
    schema = "reporting_migration_#{SecureRandom.hex(6)}"
    original_path = connection.schema_search_path
    connection.execute("CREATE SCHEMA #{schema}")
    connection.schema_search_path = schema
    connection.execute("CREATE TABLE hosts (id bigint PRIMARY KEY, external_id varchar NOT NULL)")
    connection.execute("CREATE TABLE host_snapshots (id bigint PRIMARY KEY, details jsonb NOT NULL)")
    connection.execute("INSERT INTO hosts VALUES (1, 'legacy-host')")
    connection.execute("INSERT INTO host_snapshots VALUES (1, '{\"boot_id\":\"retained-boot\",\"selinux\":{\"enforcement\":\"permissive\"}}')")
    before = connection.select_all("SELECT * FROM host_snapshots").to_a

    described_class.new.migrate(:up)

    expect(connection.select_value("SELECT count(*) FROM host_reporting_days")).to eq(0)
    cursor = connection.select_one("SELECT external_id, reporting_started_at, reporting_observed_at, reporting_received_at, reporting_boot_id, reporting_sample_status FROM hosts")
    expect(cursor).to eq({ "external_id" => "legacy-host", "reporting_started_at" => nil, "reporting_observed_at" => nil,
      "reporting_received_at" => nil, "reporting_boot_id" => nil, "reporting_sample_status" => nil })
    expect(connection.select_all("SELECT * FROM host_snapshots").to_a).to eq(before)
    expect { connection.execute("UPDATE hosts SET reporting_sample_status = 'healthy'") }.to raise_error(ActiveRecord::StatementInvalid)
    insert = "INSERT INTO host_reporting_days (host_id, observed_on, credited_microseconds, created_at, updated_at) VALUES (1, '2026-10-13', %s, NOW(), NOW())"
    expect { connection.execute(insert % -1) }.to raise_error(ActiveRecord::StatementInvalid)
    expect { connection.execute(insert % 86_400_000_001) }.to raise_error(ActiveRecord::StatementInvalid)
    connection.execute(insert % 0)
    expect { connection.execute(insert % 0) }.to raise_error(ActiveRecord::RecordNotUnique)
    connection.execute("DELETE FROM hosts WHERE id = 1")
    expect(connection.select_value("SELECT count(*) FROM host_reporting_days")).to eq(0)
    expect(connection.select_all("SELECT * FROM host_snapshots").to_a).to eq(before)
  ensure
    connection.schema_search_path = original_path if original_path
    connection.execute("DROP SCHEMA IF EXISTS #{schema} CASCADE") if schema
    connection.schema_cache.clear!
  end
end
