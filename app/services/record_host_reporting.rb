class RecordHostReporting
  # Called inside heartbeat's host lock/transaction, before snapshot coalescing.
  def self.call(host, observed_at:, received_at:, boot_id:, enforcement:)
    observed_at = observed_at.utc.change(usec: observed_at.usec)
    received_at = received_at.utc.change(usec: received_at.usec)
    previous = host.reporting_observed_at
    return if previous && observed_at <= previous
    if host.reporting_boot_id && boot_id != host.reporting_boot_id
      return if host.host_snapshots.where("details ->> 'boot_id' = ?", boot_id).where("created_at < ?", host.reporting_received_at).exists?
    end

    ds = previous && observed_at.to_r - previous.to_r
    dr = host.reporting_received_at && received_at.to_r - host.reporting_received_at.to_r
    timing_bad = (observed_at.to_r - received_at.to_r).abs > HostReportingDay::MAX_INTERVAL || (dr && dr <= 0)
    eligible = %w[enforcing permissive].include?(enforcement)
    pair = !timing_bad && eligible && host.reporting_boot_id == boot_id &&
      %w[eligible recovering].include?(host.reporting_sample_status) &&
      ds&.positive? && dr&.positive? && ds <= HostReportingDay::MAX_INTERVAL && dr <= HostReportingDay::MAX_INTERVAL

    status = if timing_bad
      "timing_unknown"
    elsif !eligible
      "ineligible"
    elsif %w[timing_unknown recovering].include?(host.reporting_sample_status) && !pair
      "recovering"
    else
      "eligible"
    end

    if eligible && !timing_bad
      host.reporting_started_at ||= observed_at
      host.host_reporting_days.find_or_create_by!(observed_on: observed_at.to_date)
      if pair
        credit = [ds, dr, HostReportingDay::EXPECTED_INTERVAL].min
        start = observed_at - credit
        while start < observed_at
          finish = [start.tomorrow.beginning_of_day, observed_at].min
          day = host.host_reporting_days.find_or_initialize_by(observed_on: start.to_date)
          day.credited_microseconds = (day.credited_microseconds || 0) + ((finish.to_r - start.to_r) * HostReportingDay::MICROSECONDS).to_i
          day.save!
          start = finish
        end
      end
    end
    host.update!(reporting_observed_at: observed_at, reporting_received_at: received_at,
      reporting_boot_id: boot_id, reporting_sample_status: status, reporting_started_at: host.reporting_started_at)
  end
end
