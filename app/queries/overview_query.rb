class OverviewQuery
  Result = Struct.new(:metrics, :series, :attention, keyword_init: true)

  def call
    now = Time.current
    Result.new(metrics: metrics(now), series: series(now), attention: attention)
  end

  private

  def metrics(now)
    {
      active_issues: IssueQuery.new.count,
      new_issues_24h: IssueQuery.new(filters: { "status" => "all", "new" => "1" }).count,
      affected_hosts: Occurrence.joins(:issue).where(issues: { status: "open" }).distinct.count(:host_id),
      avcs_24h: Occurrence.where(occurred_at: 24.hours.ago..now).count,
      monitored_hosts: Host.count,
      agent_states: HostListQuery.agent_state_counts(hosts)
    }
  end

  def series(now)
    {
      new_issues: daily_series(Issue.where(first_seen_at: 7.days.ago..now).pluck(:first_seen_at), now),
      avc_occurrences: daily_series(Occurrence.where(occurred_at: 7.days.ago..now).pluck(:occurred_at), now)
    }
  end

  def attention
    {
      agent_states: agent_state_groups(hosts),
      permissive: permissive_attention(hosts),
      new_issues: new_issue_attention,
      multi_host_issues: multi_host_attention
    }
  end

  def hosts
    @hosts ||= Host.includes(:agent_installations, current_state_observation: :host_snapshot).to_a
  end

  def agent_state_groups(hosts)
    AgentInstallation::REPORTING_STATES.filter_map do |state|
      next if state == "reporting"

      matching = hosts.select { |host| HostListQuery.host_agent(host)&.reporting_state == state }
      next if matching.empty?

      times = matching.filter_map { |host| HostListQuery.host_agent(host)&.last_seen_at }.sort
      {
        state: state,
        host_count: matching.size,
        heartbeat_range: times.empty? ? nil : [times.first, times.last],
        example_hosts: host_examples(matching)
      }
    end
  end

  def permissive_attention(hosts)
    matching = hosts.select do |host|
      host.current_configuration? && host.enforcement_for == "permissive"
    end
    return nil if matching.empty?

    { host_count: matching.size, example_hosts: host_examples(matching) }
  end

  def new_issue_attention
    issues = Issue.where(status: "open", first_seen_at: 24.hours.ago..)
    return nil if issues.empty?

    { issue_count: issues.count, example_issues: issue_examples(issues.order(first_seen_at: :desc).limit(3)) }
  end

  def multi_host_attention
    query = IssueQuery.new(filters: { "multiple_hosts" => "1" })
    count = query.count
    return nil if count.zero?

    { issue_count: count, example_issues: issue_examples(query.call.issues.first(3)) }
  end

  def daily_series(timestamps, now)
    tallied = timestamps.group_by { |timestamp| timestamp.to_date }.transform_values(&:size)
    (6.days.ago.to_date..now.to_date).map do |date|
      { date: date.iso8601, value: tallied.fetch(date, 0) }
    end
  end

  def host_examples(hosts)
    hosts.first(3).map { |host| { id: host.id, hostname: host.hostname.presence } }
  end

  def issue_examples(issues)
    issues.map { |issue| { id: issue.id, source_type: issue.source_type, target_type: issue.target_type } }
  end
end
