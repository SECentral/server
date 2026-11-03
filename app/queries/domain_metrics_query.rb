class DomainMetricsQuery
  ENFORCEMENT_STATES = %w[enforcing permissive disabled unknown].freeze

  Result = Struct.new(:issues, :regressed_issues, :occurrences, :ungrouped_occurrences,
    :hosts, :hosts_by_selinux_enforcement, :hosts_with_open_issues, :agent_installations, keyword_init: true)

  def call
    now = Time.current
    enforcement = enforcement_counts(now)
    Result.new(
      issues: Issue.group(:status, :disposition).count,
      regressed_issues: Issue.where(status: "open").where.not(reopened_at: nil)
        .where("resolved_at IS NULL OR reopened_at > resolved_at").count,
      occurrences: Occurrence.count,
      ungrouped_occurrences: Occurrence.where(issue_id: nil).count,
      hosts: enforcement.values.sum,
      hosts_by_selinux_enforcement: enforcement,
      hosts_with_open_issues: Occurrence.joins(:issue).where(issues: { status: "open" }).distinct.count(:host_id),
      agent_installations: agent_counts(now))
  end

  private

  def agent_counts(now)
    ApplicationRecord.with_connection do |connection|
      thresholds = Rails.application.config.x.agent_reporting
      state = <<~SQL.squish
        CASE
          WHEN last_seen_at IS NULL OR last_seen_at <= #{connection.quote(now - thresholds.offline_after)} THEN 'offline'
          WHEN last_seen_at <= #{connection.quote(now - thresholds.stale_after)} THEN 'stale'
          ELSE 'reporting'
        END
      SQL
      AgentInstallation.group(Arel.sql(state)).count
    end
  end

  def enforcement_counts(now)
    ApplicationRecord.with_connection do |connection|
      cutoff = connection.quote(now - Rails.application.config.x.agent_reporting.stale_after)
      # Match CheckpointTrust.for_host's evidence selection, including its boot scope.
      # EXISTS avoids multiplying a host by its event or observation history.
      sql = <<~SQL
        SELECT state, COUNT(*) AS count FROM (
          SELECT CASE
            WHEN observation.id IS NULL OR observation.last_received_at < #{cutoff} THEN 'unknown'
            WHEN EXISTS (
              SELECT 1 FROM raw_events event
              WHERE event.host_id = hosts.id
                AND event.boot_id = snapshot.details ->> 'boot_id'
                AND event.audit_timestamp >= observation.last_observed_at
                AND (event.transition_type IS NOT NULL OR
                  (event.category = 'avc' AND event.checkpoint_invalidated_fields <> '[]'::jsonb))
                AND ('enforcement' = ANY(#{CheckpointTrust.transition_fields_sql('event.transition_type')})
                  OR event.checkpoint_invalidated_fields ? 'enforcement')
            ) THEN 'unknown'
            WHEN snapshot.details #>> '{selinux,enforcement}' IN ('enforcing', 'permissive', 'disabled')
              THEN snapshot.details #>> '{selinux,enforcement}'
            ELSE 'unknown'
          END AS state
          FROM hosts
          LEFT JOIN (
            SELECT DISTINCT ON (host_id) id, host_id, host_snapshot_id, last_received_at, last_observed_at
            FROM host_snapshot_observations
            ORDER BY host_id, last_received_at DESC, id DESC
          ) observation ON observation.host_id = hosts.id
          LEFT JOIN host_snapshots snapshot ON snapshot.id = observation.host_snapshot_id
        ) classified
        GROUP BY state
      SQL
      connection.select_all(sql, "Domain metrics enforcement").to_h { |row| [row.fetch("state"), row.fetch("count").to_i] }
    end
  end
end
