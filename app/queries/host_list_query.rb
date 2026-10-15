class HostListQuery
  Result = Struct.new(:hosts, :total_count, :page, :page_size, :agent_state_counts, keyword_init: true)

  def initialize(filters: {}, page: 1, limit: nil)
    @filters = filters.transform_keys(&:to_s)
    @page = [page.to_i, 1].max
    @page_size = PageSize.parse(limit)
  end

  def call
    hosts = filtered_hosts
    Result.new(
      hosts: hosts.slice((@page - 1) * @page_size, @page_size) || [],
      total_count: hosts.size,
      page: @page,
      page_size: @page_size,
      agent_state_counts: self.class.agent_state_counts(hosts)
    )
  end

  def self.host_agent(host)
    host.agent_installations.max_by { |installation| installation.last_seen_at || Time.at(0) }
  end

  def self.agent_state_counts(hosts)
    counts = AgentInstallation::REPORTING_STATES.index_with { 0 }
    hosts.each do |host|
      counts[host_agent(host)&.reporting_state || "offline"] += 1
    end
    counts
  end

  private

  def filtered_hosts
    hosts = Host.includes(:host_snapshots, :agent_installations, current_state_observation: :host_snapshot).order(:hostname, :external_id)
    hosts = hosts.where(id: @filters["host_id"]) if @filters["host_id"].present?
    current_observations = HostSnapshotObservation.where("last_received_at >= ?", stale_after.ago)
      .select("DISTINCT ON (host_id) host_snapshot_id")
      .order("host_id, last_received_at DESC, id DESC")
    if @filters["os_id"].present?
      hosts = hosts.joins(:host_snapshots).where(host_snapshots: { id: current_observations })
        .where("host_snapshots.details #>> '{platform,os_id}' = ?", @filters["os_id"])
    end
    if @filters["policy_type"].present?
      hosts = hosts.joins(:host_snapshots).where(host_snapshots: { id: current_observations })
        .where("host_snapshots.details #>> '{selinux,configured_policy_type}' = ?", @filters["policy_type"])
    end
    if @filters["kernel_policy_version"].present?
      hosts = hosts.joins(:host_snapshots).where(host_snapshots: { id: current_observations })
        .where("host_snapshots.details #>> '{selinux,kernel_policy_version}' = ?", @filters["kernel_policy_version"])
    end
    hosts = hosts.joins(:agent_installations)
      .where(agent_installations: { agent_version: @filters["agent_version"] }) if @filters["agent_version"].present?
    hosts = hosts.to_a
    if @filters["enforcement"].present?
      hosts = hosts.select { |host| host.current_configuration? && host.enforcement_for == @filters["enforcement"] }
    end
    if AgentInstallation::REPORTING_STATES.include?(@filters["status"])
      hosts = hosts.select { |host| self.class.host_agent(host)&.reporting_state == @filters["status"] }
    end
    hosts
  end

  def stale_after
    Rails.application.config.x.agent_reporting.stale_after
  end
end
