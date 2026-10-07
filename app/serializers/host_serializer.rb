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
      counts: counts
    }
    payload[:snapshot] = snapshot ? { platform: platform, selinux: selinux } : nil if include_snapshot
    payload
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
