class HostEnforcingReadiness
  TARGET_SECONDS = 30 * 86_400

  def self.call(host, at: Time.current, checkpoint_enforcement: nil)
    reason = unknown_reason(host, at, checkpoint_enforcement)
    latest_avc_at = host.raw_events.where(category: "avc").maximum(:audit_timestamp)
    reason ||= "denial_time_unavailable" if latest_avc_at && latest_avc_at > at
    basis = { target_days: 30, capture_continuity: "unknown", reporting_started_at: host.reporting_started_at, latest_avc_at: latest_avc_at }
    return basis.merge(status: "unknown", reason: reason, band: nil, credited_seconds: nil, reporting_days: nil) if reason

    days = host.host_reporting_days
    # ponytail: exclude the whole denial day; use finer buckets only if sub-day progress matters.
    days = days.where("observed_on > ?", latest_avc_at.utc.to_date) if latest_avc_at
    microseconds = days.sum(:credited_microseconds)
    percent = [100, microseconds * 100 / (TARGET_SECONDS * HostReportingDay::MICROSECONDS)].min
    band = percent == 100 ? "100%" : "#{percent / 20 * 20}–#{percent / 20 * 20 + 19}%"
    basis.merge(status: "observed", reason: nil, band: band,
      credited_seconds: microseconds.fdiv(HostReportingDay::MICROSECONDS), reporting_days: (microseconds * 10 / (86_400 * HostReportingDay::MICROSECONDS)).fdiv(10))
  end

  def self.unknown_reason(host, at, checkpoint_enforcement)
    return "reporting_not_tracked" unless host.reporting_observed_at && host.reporting_received_at
    return "reporting_time_unknown" if %w[timing_unknown recovering].include?(host.reporting_sample_status)
    return "enforcement_unavailable" unless host.reporting_sample_status == "eligible"
    return "reporting_not_tracked" unless host.reporting_started_at
    return "reporting_time_unknown" if host.reporting_received_at > at || host.reporting_observed_at > at + HostReportingDay::MAX_INTERVAL
    return "reporting_stale" if [host.reporting_observed_at, host.reporting_received_at].min <= at - HostReportingDay::MAX_INTERVAL

    observation = host.current_state_observation
    return "checkpoint_unavailable" unless observation
    return "checkpoint_boot_mismatch" unless observation.host_snapshot.details["boot_id"] == host.reporting_boot_id
    checkpoint_enforcement ||= host.enforcement_for(observation)
    "enforcement_unavailable" unless %w[enforcing permissive].include?(checkpoint_enforcement)
  end
  private_class_method :unknown_reason
end
