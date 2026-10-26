class HostSerializer
  def self.call(host, counts: {}, include_snapshot: false)
    agent = HostListQuery.host_agent(host)
    observation = host.current_state_observation
    snapshot = observation&.host_snapshot
    platform = platform_payload(snapshot&.details)
    state = host.selinux_state_for(observation)
    selinux = selinux_payload({ "selinux" => state }, include_identity: include_snapshot, policy_identity: state["policy_identity"])
    selinux[:effective_permissive_domains] = PolicyPermissiveDomains.lookup(state["policy_identity"]) if include_snapshot
    payload = {
      id: host.id,
      hostname: host.hostname,
      external_id: host.external_id,
      last_seen_at: host.last_seen_at,
      agent: {
        reporting_state: agent&.reporting_state || "offline",
        agent_version: agent&.agent_version,
        last_seen_at: agent&.last_seen_at
      },
      observation: observation_payload(observation),
      platform: platform,
      selinux: selinux,
      telemetry: { audit_capture: "unknown", explanation: "Agent reporting and configuration freshness do not establish continuous audit capture." },
      counts: counts
    }
    payload[:snapshot] = snapshot ? { platform: platform, selinux: selinux } : nil if include_snapshot
    if include_snapshot
      payload[:reporting_observations] = enforcing_readiness_payload(host, enforcement: state["enforcement"])
      payload[:enforcing_readiness] = payload[:reporting_observations]
    end
    payload
  end

  def self.enforcing_readiness_payload(host, enforcement:)
    result = HostEnforcingReadiness.call(host, checkpoint_enforcement: enforcement)
    explanation = if result[:status] == "observed"
      days = result[:reporting_days].zero? && result[:credited_seconds].positive? ? "less than 0.1" : format("%.1f", result[:reporting_days])
      "SECentral has accumulated #{days} days of credited agent-reporting intervals strictly after the latest retained AVC's UTC day (or since tracking began if none). " \
        "Gaps are not credited; this is not continuous observation or workload coverage. " \
        "Audit capture continuity is unknown. Reporting duration does not establish suitability for enforcing mode."
    else
      reason = {
        "reporting_not_tracked" => "reporting duration has not yet been tracked from a usable heartbeat",
        "reporting_time_unknown" => "reporting timestamps are ambiguous or timing recovery is incomplete",
        "enforcement_unavailable" => "current SELinux enforcement evidence is missing, disabled or untrusted",
        "reporting_stale" => "the reporting observation is stale",
        "checkpoint_unavailable" => "a current heartbeat checkpoint is unavailable",
        "checkpoint_boot_mismatch" => "the current checkpoint and reporting cursor refer to different boots",
        "denial_time_unavailable" => "the recorded AVC timestamp is later than the evaluation time"
      }.fetch(result[:reason], "usable reporting evidence is unavailable")
      "Credited reporting duration is Unknown because #{reason}. " \
        "Reporting time is not credited without usable, fresh evidence. " \
        "Audit capture coverage is unknown; this indicator cannot establish that enforcing mode is safe."
    end
    result.merge(explanation: explanation)
  end

  def self.observation_payload(observation)
    return { status: "none", last_received_at: nil, last_observed_at: nil } unless observation

    {
      status: observation.stale? ? "stale" : "current",
      last_received_at: observation.last_received_at,
      last_observed_at: observation.last_observed_at
    }
  end

  def self.platform_payload(details)
    platform = (details || {}).fetch("platform", {})
    { os_id: platform["os_id"], os_version: platform["os_version"] }.tap do |payload|
      payload[:architecture] = platform["architecture"] if platform.key?("architecture")
    end
  end

  def self.selinux_payload(details, include_identity: false, policy_identity: nil)
    selinux = (details || {}).fetch("selinux", {})
    payload = {
      enforcement: selinux["enforcement"],
      configured_policy_type: selinux["configured_policy_type"],
      kernel_policy_version: selinux["kernel_policy_version"]
    }
    payload[:policy_identity] = policy_identity if include_identity
    payload
  end
end
