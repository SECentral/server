# Run with rails runner against a disposable secentral_log_benchmark database.
abort "Requires the dedicated test benchmark database" unless Rails.env.test? && ActiveRecord::Base.connection_db_config.database == "secentral_log_benchmark"
$stdout.sync = true

connection = ActiveRecord::Base.connection
sizes = ENV.fetch("LOG_BENCHMARK_SIZES", "100000,1000000").split(",").map { |size| Integer(size) }
abort "Unsupported benchmark size" unless (sizes - [100_000, 1_000_000]).empty?
now = Time.utc(2026, 10, 13, 12)
report = { postgres: connection.select_value("SELECT version()"), cpu: File.read("/proc/cpuinfo")[/^model name\s*:\s*(.*)$/, 1], memory: File.read("/proc/meminfo")[/^MemTotal:\s*(.*)$/, 1], datasets: [] }
ENV["ADMIN_USERNAME"] = "benchmark"
ENV["ADMIN_PASSWORD_DIGEST"] = BCrypt::Password.create("benchmark-password").to_s

sizes.each do |total|
  connection = ActiveRecord::Base.connection
  count = total == 100_000 ? 100 : 1000
  connection.execute("TRUNCATE organizations, hosts, agent_installations, raw_events, raw_audit_records, normalized_denials, occurrences RESTART IDENTITY CASCADE")
  organization = Organization.create!(name: "benchmark")
  puts "Seeding #{total} entries across #{count} hosts"
  seed_sql = <<~SQL
    INSERT INTO hosts (id, organization_id, external_id, hostname, created_at, updated_at)
    SELECT g, #{organization.id}, 'host-' || g, 'host-' || g, NOW(), NOW() FROM generate_series(1, #{count}) g;
    INSERT INTO agent_installations (id, organization_id, name, created_at, updated_at)
    VALUES (1, #{organization.id}, 'benchmark', NOW(), NOW());
    INSERT INTO raw_events (id, organization_id, agent_installation_id, host_id, category, transition_type,
      audit_timestamp, audit_sequence, boot_id, completion_reason, evidence_digest,
      agent_received_at, server_received_at, schema_version, created_at, updated_at,
      boolean_changes, enforcement_changes, port_changes, file_context_changes)
    SELECT g, #{organization.id}, 1, CASE WHEN g <= #{total / 2} THEN 1 ELSE 2 + ((g - #{total / 2} - 1) % #{count - 1}) END,
      CASE WHEN g % 10 = 0 THEN 'selinux_administrative' ELSE 'avc' END,
      CASE WHEN g % 10 = 0 THEN (ARRAY['policy_load','boolean_change','enforcement_change','port_change','file_context_change'])[1 + (g / 10) % 5] END,
      TIMESTAMP '#{now.iso8601(6)}' - INTERVAL '30 days' + (g / 2) * INTERVAL '60 days' / #{total},
      g, 'boot', 'eoe', repeat('a', 64), NOW(), NOW(), 4, NOW(), NOW(),
      CASE WHEN g % 50 = 10 THEN '[{"name":"httpd_can_network_connect","old_value":0,"new_value":1,"success":true}]'::jsonb ELSE '[]'::jsonb END,
      CASE WHEN g % 50 = 20 THEN '[{"old_mode":"enforcing","new_mode":"permissive","success":true}]'::jsonb ELSE '[]'::jsonb END,
      CASE WHEN g % 50 = 30 THEN '[{"operation":"modify","protocol":"tcp","start":8080,"end":8080,"target_context":"system_u:object_r:http_port_t:s0","selinux_type":"http_port_t","success":true}]'::jsonb ELSE '[]'::jsonb END,
      CASE WHEN g % 50 = 40 THEN '[{"operation":"modify","expression":"/srv/data","file_selector":"any","target_context":"system_u:object_r:var_t:s0","selinux_type":"var_t","success":true}]'::jsonb ELSE '[]'::jsonb END
    FROM generate_series(1, #{total}) g;
    INSERT INTO raw_audit_records (raw_event_id, position, record_type, type_name, audit_timestamp, sequence, payload, created_at, updated_at)
    SELECT id, 0, 1300, 'SYSCALL', audit_timestamp, audit_sequence, convert_to('auid=0 uid=0 comm="semanage"', 'UTF8'), NOW(), NOW()
    FROM raw_events WHERE category = 'selinux_administrative';
    INSERT INTO normalized_denials (id, raw_event_id, ordinal, normalization_version, status,
      source_type, target_type, target_class, permissions, target_paths, command, details, created_at, updated_at)
    SELECT id, id, 0, 1, 'ungroupable', 'httpd_t', 'var_t', 'file', '["read"]'::jsonb, '["/srv/data"]'::jsonb, 'httpd', '{"permissive":true}'::jsonb, NOW(), NOW()
    FROM raw_events WHERE category = 'avc';
    INSERT INTO occurrences (id, organization_id, host_id, raw_event_id, normalized_denial_id, occurred_at, created_at, updated_at)
    SELECT id, organization_id, host_id, id, id, audit_timestamp, NOW(), NOW() FROM raw_events WHERE category = 'avc';
    ANALYZE hosts; ANALYZE raw_events; ANALYZE raw_audit_records; ANALYZE normalized_denials; ANALYZE occurrences;
  SQL
  seed_sql.split(";\n").each do |statement|
    puts "  #{statement.lines.first.strip}"
    connection.execute(statement)
  end
  session = ActionDispatch::Integration::Session.new(Rails.application)
  session.post("/api/v1/sessions", params: { username: "benchmark", password: "benchmark-password" })
  raise "Login failed" unless session.response.status == 201
  dataset = { hosts: count, entries: total, indexes: connection.select_rows("SELECT indexname, indexdef FROM pg_indexes WHERE tablename IN ('raw_events', 'occurrences') ORDER BY indexname"), cases: [] }
  cases = { "all-retained" => {}, "24h" => { "start" => (now - 1.day).iso8601(6), "end" => (now + 1).iso8601(6) },
    "avc" => { "category" => "avc" }, "administrative" => { "category" => "administrative" },
    "busy-host" => { "host_id" => "1" }, "quiet-host" => { "host_id" => count.to_s } }
  cases.each do |name, filters|
    [1, 50].each do |limit|
      first = filters.merge("limit" => limit.to_s)
      cursor = SelinuxLogQuery.new(organization: organization, filters: first).call.dig(:meta, :next_cursor)
      [first, cursor ? first.merge("before" => cursor) : nil].compact.each_with_index do |params, page|
        counts = []
        timings = []
        21.times do
          queries = 0
          subscriber = ActiveSupport::Notifications.subscribe("sql.active_record") { |event| queries += 1 unless %w[SCHEMA TRANSACTION].include?(event.payload[:name]) || event.payload[:cached] }
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          session.get("/api/v1/selinux-log", params: params)
          elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
          ActiveSupport::Notifications.unsubscribe(subscriber)
          raise session.response.body unless session.response.status == 200
          raise "Unbounded page" if JSON.parse(session.response.body)["items"].size > limit
          counts << queries
          timings << elapsed * 1000
        end
        query = SelinuxLogQuery.new(organization: organization, filters: params)
        plan = ActiveRecord::Base.connection.select_rows("EXPLAIN (ANALYZE, BUFFERS) #{query.sql}").flatten
        warm = timings.drop(1).sort
        result = { name: name, limit: limit, page: page + 1, first_run_ms: timings.first.round(2), median_ms: ((warm[9] + warm[10]) / 2).round(2), p95_ms: warm[18].round(2), queries: counts.uniq, plan: plan }
        dataset[:cases] << result
        puts result.except(:plan).merge(entries: total).to_json
      end
    end
  end
  report[:datasets] << dataset
  File.write("/tmp/selinux-log-benchmark.json", JSON.pretty_generate(report))
end
puts "Full query plans and environment: /tmp/selinux-log-benchmark.json"
