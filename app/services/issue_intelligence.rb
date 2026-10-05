class IssueIntelligence
  def self.destination_ports(details)
    network = details.to_h.fetch("network_evidence", {})
    (Array(network["dport_fields"]) + Array(network["dest_fields"]))
      .filter_map { |value| value.to_s if value.to_s.match?(/\A\d+\z/) && value.to_i.between?(0, 65_535) }.uniq
  end

  def self.call(issue)
    new(issue).call
  end

  def initialize(issue)
    @issue = issue
  end

  def call
    rows = @issue.occurrences.joins(:host, :normalized_denial, :raw_event).pluck(
      "occurrences.host_id", "hosts.hostname", "normalized_denials.details",
      "normalized_denials.source_context", "normalized_denials.target_context",
      "normalized_denials.command", "normalized_denials.executable", "occurrences.id",
      "occurrences.raw_event_id", "raw_events.file_context_observations", "occurrences.occurred_at",
      "raw_events.host_observed_at", "raw_events.boot_id"
    )
    activity_hosts = Host.where(organization: @issue.organization).where("last_seen_at >= ?", Host::STALE_AFTER.ago).includes(current_state_observation: :host_snapshot).to_a
    configuration_hosts = activity_hosts.select(&:current_configuration?)
    affected_ids = rows.map(&:first).uniq
    destination_ports = if @issue.target_class == "tcp_socket" && @issue.permissions.include?("name_connect")
      rows.flat_map { |row| self.class.destination_ports(row[2]) }.tally
    else
      {}
    end
    intelligence = {
      occurrence_summaries: occurrence_summaries,
      paths: rows.flat_map { |row| target_evidence(row[2])["filesystem_paths"] }.uniq.sort,
      names: rows.flat_map { |row| target_evidence(row[2])["object_names"] }.uniq.sort,
      resource_summary: {
        absolute_path_occurrences: rows.count { |row| target_evidence(row[2])["filesystem_paths"].present? },
        without_absolute_path_occurrences: rows.count { |row| target_evidence(row[2])["filesystem_paths"].empty? },
        destination_port_count: destination_ports.size,
        destination_ports: destination_ports.sort_by { |port, count| [ -count, port.to_i ] }.first(3)
          .map { |port, count| { port: port, occurrence_count: count } }
      },
      executables: rows.map { |row| row[6] }.compact.uniq.sort,
      commands: rows.map { |row| row[5] }.compact.uniq.sort,
      network_evidence: rows.flat_map { |row| [ row[2].to_h.fetch("network_evidence", {}) ] }.then { |values| merge_network_evidence(values) },
      process_evidence: rows.flat_map { |row| [ row[2].to_h.fetch("process_evidence", {}) ] }.then { |values| merge_process_evidence(values) },
       contexts: rows.filter_map { |row| { source: row[3], target: row[4] } if row[3] || row[4] }.uniq,
       observed_target_contexts: rows.filter_map { |row| row[4] }.uniq,
        event_file_contexts: rows.flat_map { |row| Array(row[2].to_h["event_file_contexts"]) },
        expected_context_observations: expected_context_observations(rows),
        correlated_file_contexts: correlated_file_contexts(rows),
      affected_hosts: @issue.occurrences.distinct.count(:host_id),
      occurrence_time: {
        affected_occurrences: @issue.occurrences.count,
        affected_hosts: @issue.occurrences.distinct.count(:host_id),
        platform_distribution: snapshot_distribution("platform,os_version"),
        policy_distribution: snapshot_distribution("selinux,kernel_policy_version"),
        enforcement_distribution: snapshot_distribution("selinux,enforcement")
      },
        fleet: fleet_comparison(configuration_hosts, affected_ids, activity_hosts.size),
        current_file_context_matches: current_file_context_matches(configuration_hosts),
        configuration_drift: configuration_drift(configuration_hosts, affected_ids),
       policy_evaluation: PolicyEvaluation.call(@issue)
    }
    intelligence[:explanation] = SelinuxExplanation.call(@issue, intelligence: intelligence)
    intelligence
  end

  private

  def occurrence_summaries
    evidence_sql = <<~SQL.squish
      CROSS JOIN LATERAL (
        SELECT 'path'::text AS kind, jsonb_array_elements_text(
          COALESCE(normalized_denials.details->'target_evidence'->'filesystem_paths', '[]'::jsonb)
        ) AS target
        UNION ALL
        SELECT 'name'::text AS kind, jsonb_array_elements_text(
          COALESCE(normalized_denials.details->'target_evidence'->'object_names', '[]'::jsonb)
        ) AS target
        UNION ALL
        SELECT NULL::text AS kind, NULL::text AS target
        WHERE COALESCE(jsonb_array_length(normalized_denials.details->'target_evidence'->'filesystem_paths'), 0) = 0
          AND COALESCE(jsonb_array_length(normalized_denials.details->'target_evidence'->'object_names'), 0) = 0
      ) evidence
    SQL

    @issue.occurrences.joins(:host, :normalized_denial).joins(evidence_sql)
      .group("occurrences.host_id", "hosts.hostname", "evidence.kind", "evidence.target")
      .order(Arel.sql("COUNT(*) DESC, hosts.hostname, evidence.kind, evidence.target"))
      .pluck("occurrences.host_id", "hosts.hostname", "evidence.kind", "evidence.target", Arel.sql("COUNT(*)"), Arel.sql("MIN(occurrences.occurred_at)"), Arel.sql("MAX(occurrences.occurred_at)"), Arel.sql("(array_agg(occurrences.id ORDER BY occurrences.occurred_at DESC, occurrences.id DESC))[1]"))
      .map do |host_id, hostname, kind, target, count, first_seen_at, last_seen_at, occurrence_id|
        { host_id: host_id, hostname: hostname, kind: kind, target: target, count: count,
          first_seen_at: first_seen_at, last_seen_at: last_seen_at, evidence_occurrence_id: occurrence_id }
      end
  end

  def target_evidence(details)
    details.to_h.fetch("target_evidence", {}).reverse_merge("path_fields" => [], "filesystem_paths" => [], "object_names" => [])
  end

  def snapshot_distribution(path)
    if path == "selinux,enforcement"
      expression = "CASE WHEN raw_events.checkpoint_invalidated_fields ? 'enforcement' THEN 'unknown' ELSE host_snapshots.details #>> '{selinux,enforcement}' END"
      return @issue.occurrences.joins(:raw_event, :host_snapshot).group(Arel.sql(expression)).count
        .reject { |value, _count| value.nil? }.sort_by { |value, count| [-count, value] }.to_h
    end
    counts = @snapshot_counts ||= @issue.occurrences.where.not(host_snapshot_id: nil).group(:host_snapshot_id).count
    expression = "host_snapshots.details #>> '{#{path}}'"
    totals = Hash.new(0)
    HostSnapshot.where(id: counts.keys).pluck(:id, Arel.sql(expression)).each do |id, value|
      totals[value] += counts.fetch(id) unless value.nil?
    end
    totals.sort_by { |value, count| [ -count, value ] }.to_h
  end

  def merge_network_evidence(values)
    network_evidence_defaults.to_h { |key| [key, values.flat_map { |value| Array(value[key]) }.uniq.sort] }
  end

  def network_evidence_defaults
    %w[dest_fields dport_fields lport_fields proto_fields bind_port_fields operations]
  end

  def merge_process_evidence(values)
    process_evidence_defaults.to_h { |key| [key, values.flat_map { |value| Array(value[key]) }.uniq.sort] }
  end

  def process_evidence_defaults
    %w[pids commands executables source_contexts]
  end

  def distribution(details, path)
    details.map { |value| path.reduce(value || {}) { |current, key| current.is_a?(Hash) ? current[key] : nil } }.compact.tally.sort_by { |value, count| [-count, value.to_s] }.to_h
  end

  def fleet_comparison(configuration_hosts, affected_ids, activity_host_count)
    affected = configuration_hosts.select { |host| affected_ids.include?(host.id) }
    unaffected = configuration_hosts.reject { |host| affected_ids.include?(host.id) }
    { activity_hosts: activity_host_count, current_configuration_hosts: configuration_hosts.size, hosts_with_occurrence: affected.size, hosts_without_occurrence: unaffected.size,
      with_occurrence_platforms: host_distribution(affected, ["platform", "os_id", "os_version"]),
      without_occurrence_platforms: host_distribution(unaffected, ["platform", "os_id", "os_version"]),
       with_occurrence_policies: host_distribution(affected, ["selinux", "kernel_policy_version"]),
       without_occurrence_policies: host_distribution(unaffected, ["selinux", "kernel_policy_version"]),
       with_occurrence_modules: module_distribution(affected), without_occurrence_modules: module_distribution(unaffected),
       with_occurrence_file_contexts: file_context_distribution(affected), without_occurrence_file_contexts: file_context_distribution(unaffected) }
  end

  def host_distribution(hosts, path)
    distribution(hosts.map { |host| host.current_snapshot&.details }, path)
  end

  def module_distribution(hosts)
    hosts.flat_map do |host|
      policy = host.current_snapshot&.details&.dig("selinux", "policy") || {}
      modules = Array(policy["modules"])
      modules = Array(policy["custom_modules"]).map { |mod| mod.merge("provenance" => "unknown") } if modules.empty?
      modules.map { |mod| [mod["name"], mod["priority"], mod.fetch("provenance", "unknown")] }
    end.tally
  end

  def file_context_distribution(hosts)
    hosts.flat_map do |host|
      Array(host.current_snapshot&.details&.dig("selinux", "policy", "file_contexts")).map do |mapping|
        [mapping["pattern"], mapping["file_type"], mapping["context"], mapping.fetch("provenance", "unknown")]
      end
    end.tally
  end

  def current_file_context_matches(hosts)
    paths = rows_for_file_contexts
    hosts.flat_map do |host|
      mappings = host.current_snapshot&.details&.dig("selinux", "policy", "file_contexts")
      paths.flat_map do |path|
        result = FileContextMatcher.call(path, mappings)
        result[:matches].map { |mapping| { host_id: host.id, hostname: host.hostname, path: path, mapping: mapping, temporal_scope: "current_configuration_fleet" } }
      end
    end
  end

  def rows_for_file_contexts
    @issue.occurrences.joins(:normalized_denial).pluck("normalized_denials.details").flat_map do |details|
      target_evidence(details)["filesystem_paths"]
    end.uniq
  end

  def correlated_file_contexts(rows)
    rows.flat_map do |row|
      Array(row[2].to_h["event_file_contexts"]).map { |observation| observation.merge(host_id: row[0], occurrence_id: row[7]) }
    end
  end

  def expected_context_observations(rows)
    rows.flat_map do |row|
      target = target_evidence(row[2])
      observations = Array(row[9])
      legacy = Array(row[2].to_h["event_file_contexts"]).reject do |item|
        observations.any? do |observation|
          observation["kind"] == "expected_context" &&
            observation["path"] == item["path"] &&
            observation["expected_context"] == item["expected_context"]
        end
      end
      (observations + legacy).filter_map do |item|
        legacy = item["kind"] != "expected_context"
        next if legacy && (item["expected_status"] != "observed" || item["expected_context"].blank?)

        {
          "path" => item["path"],
          "object_class" => item["object_class"].presence || @issue.target_class,
          "file_type" => item["file_type"].presence || matchpathcon_file_type(@issue.target_class),
          "expected_context" => item["expected_context"],
          "observed_at" => item["observed_at"],
          "resolver" => item["resolver"].presence || "legacy_matchpathcon",
          "status" => legacy ? "resolved" : item["status"],
          "reason" => item["reason"],
          host_id: row[0],
          hostname: row[1],
          occurrence_id: row[7],
          raw_event_id: row[8],
          checkpoint_observed_at: row[11],
          boot_id: row[12],
          avc_occurred_at: row[10],
          "process_command" => row[5],
          "executable" => row[6],
          "target_context" => row[4],
          "target_class" => @issue.target_class,
          "filesystem_paths" => target["filesystem_paths"]
        }
      end
    end
  end

  def matchpathcon_file_type(object_class)
    {
      "file" => "file", "dir" => "dir", "fifo_file" => "pipe", "chr_file" => "chr_file",
      "blk_file" => "blk_file", "lnk_file" => "lnk_file", "sock_file" => "sock_file"
    }[object_class]
  end

  def configuration_drift(hosts, affected_ids)
    hosts.select { |host| affected_ids.include?(host.id) }.flat_map do |host|
      ConfigurationDrift.call(host).map { |transition| transition.merge(host_id: host.id, hostname: host.hostname) }
    end
  end
end
