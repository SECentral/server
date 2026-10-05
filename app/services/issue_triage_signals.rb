class IssueTriageSignals
  RECENT_DAYS = 7
  BASELINE_DAYS = 30
  MIN_RECENT_OCCURRENCES = 3
  MIN_CORRELATED_HOSTS = 3

  def self.call(issue, evaluated_at: Time.current)
    new(issue, evaluated_at).call
  end

  def initialize(issue, evaluated_at)
    @issue = issue
    @evaluated_at = evaluated_at
    @recent_start = evaluated_at - RECENT_DAYS.days
    @baseline_start = evaluated_at - (RECENT_DAYS + BASELINE_DAYS).days
  end

  def call
    activity_hosts = Host.where(organization: @issue.organization)
      .where("last_seen_at >= ?", Host::STALE_AFTER.ago).includes(current_state_observation: :host_snapshot).to_a
    configuration_hosts = activity_hosts.select(&:current_configuration?)
    recent = @issue.occurrences.where(occurred_at: @recent_start...@evaluated_at)
    baseline = @issue.occurrences.where(occurred_at: @baseline_start...@recent_start)
    signals = []
    signals << fleet_signal(activity_hosts)
    signals << concentration_signal(recent)
    signals.concat(novelty_signal)
    signals << frequency_signal(recent, baseline)
    signals << policy_signal(configuration_hosts)

    {
      signals: signals.compact,
      evaluated_at: @evaluated_at.iso8601,
      windows: { recent_days: RECENT_DAYS, baseline_days: BASELINE_DAYS }
    }
  end

  private

  def signal(code, label, evidence, explanation, temporal_scope)
    { code: code, label: label, evidence: evidence, explanation: explanation,
      temporal_scope: temporal_scope, certainty: "derived" }
  end

  def fleet_signal(active_hosts)
    affected_ids = @issue.occurrences.where(host_id: active_hosts.map(&:id)).distinct.pluck(:host_id)
    active_count = active_hosts.size
    return if active_count.zero? || affected_ids.empty?

    percentage = affected_ids.size * 100.0 / active_count
    if percentage <= 10
      signal("fleet_outlier", "Fleet outlier", { hosts_with_occurrences: affected_ids.size, active_hosts: active_count, percentage: percentage.round(2) }, "#{affected_ids.size} of #{active_count} recently active hosts has an occurrence for this issue.", "recent_activity_fleet")
    elsif percentage >= 75
      signal("fleet_common", "Fleet commonality", { hosts_with_occurrences: affected_ids.size, active_hosts: active_count, percentage: percentage.round(2) }, "#{affected_ids.size} of #{active_count} recently active hosts has an occurrence for this issue.", "recent_activity_fleet")
    end
  end

  def concentration_signal(recent)
    counts = recent.group(:host_id).count
    total = counts.values.sum
    host_id, count = counts.max_by { |_, value| value }
    return if total < MIN_RECENT_OCCURRENCES || count * 100.0 / total < 75

    hostname = Host.where(id: host_id).pick(:hostname)
    signal("host_concentration", "Host concentration", { host_id: host_id, hostname: hostname, host_occurrences: count, recent_occurrences: total, recent_hosts_with_occurrences: counts.size, percentage: (count * 100.0 / total).round(2) }, "#{count} of #{total} recent occurrences are concentrated on #{hostname.presence || "one host"} across #{counts.size} host#{"s" unless counts.size == 1}.", "recent_occurrences")
  end

  def novelty_signal
    signals = []
    if @issue.first_seen_at >= @recent_start
      signals << signal("new_issue", "New issue", { first_seen_at: @issue.first_seen_at.iso8601, recent_days: RECENT_DAYS }, "This issue was first observed within the last #{RECENT_DAYS} days.", "retained_occurrence_history")
    end
    first_by_host = @issue.occurrences.group(:host_id).minimum(:occurred_at)
    new_hosts = first_by_host.select { |_, timestamp| timestamp >= @recent_start }.keys unless @issue.first_seen_at >= @recent_start
    new_hosts ||= []
    if new_hosts.any?
      signals << signal("new_host_issue", "New host/issue combination", { hosts: new_hosts, recent_days: RECENT_DAYS }, "This issue was first observed on #{new_hosts.size} host#{"s" unless new_hosts.one?} within the last #{RECENT_DAYS} days.", "retained_occurrence_history")
    end
    signals
  end

  def frequency_signal(recent, baseline)
    recent_count = recent.count
    baseline_count = baseline.count
    return if recent_count < MIN_RECENT_OCCURRENCES || baseline_count.zero?

    recent_rate = recent_count.to_f / RECENT_DAYS
    baseline_rate = baseline_count.to_f / BASELINE_DAYS
    return if recent_rate < baseline_rate * 2

    signal("frequency_increase", "Occurrence rate increased", { recent_occurrences: recent_count, baseline_occurrences: baseline_count, recent_daily_rate: recent_rate.round(3), baseline_daily_rate: baseline_rate.round(3), ratio: (recent_rate / baseline_rate).round(2) }, "Recent occurrence rate is at least twice the preceding #{BASELINE_DAYS}-day daily rate.", "recent_and_baseline_occurrences")
  end

  def policy_signal(configuration_hosts)
    affected_ids = @issue.occurrences.where(host_id: configuration_hosts.map(&:id)).distinct.pluck(:host_id)
    affected = configuration_hosts.select { |host| affected_ids.include?(host.id) }
    unaffected = configuration_hosts.reject { |host| affected_ids.include?(host.id) }
    affected_versions = policy_versions(affected)
    unaffected_versions = policy_versions(unaffected)
    return if affected.size < MIN_CORRELATED_HOSTS || unaffected.empty?

    correlations = affected_versions.filter_map do |version, count|
      affected_ratio = count.to_f / affected.size
      unaffected_ratio = unaffected_versions.fetch(version, 0).to_f / unaffected.size
      next unless affected_ratio >= unaffected_ratio * 2
      { policy_version: version, with_occurrence: { hosts: count, total: affected.size }, without_occurrence: { hosts: unaffected_versions.fetch(version, 0), total: unaffected.size } }
    end
    return if correlations.empty?

    signal("policy_version_correlation", "Policy-version correlation", { correlations: correlations }, "Some policy versions are more prevalent among hosts with this issue that have fresh heartbeat-confirmed configuration. Correlation does not establish causation.", "current_configuration_fleet")
  end

  def policy_versions(hosts)
    hosts.filter_map { |host| host.current_snapshot&.details&.dig("selinux", "kernel_policy_version") }.tally
  end
end
