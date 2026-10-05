class PortCatalogOverlay
  def self.call(hosts:, policy_identity:, catalog: nil)
    new(hosts, policy_identity, catalog).call
  end

  def initialize(hosts, policy_identity, catalog)
    @hosts = hosts
    @policy_identity = policy_identity
    @catalog = catalog || PortCatalog.for(policy_identity)
  end

  def call
    fresh, stale = cohort_hosts
    coverage = fresh.map { |host| inventory(host)["status"] || "unknown" }.tally
    segments = fresh.flat_map { |host| compare(host) }
    {
      cohort: @policy_identity,
      catalog: catalog_data,
      observed: {
        fresh_complete_host_count: coverage.fetch("observed", 0),
        partial_host_count: coverage.fetch("partial", 0),
        unavailable_host_count: coverage.fetch("unavailable", 0),
        unknown_host_count: coverage.fetch("unknown", 0),
        stale_host_count: stale.size,
        outside_cohort_host_count: @hosts.size - fresh.size - stale.size,
        no_current_configuration_host_count: @hosts.count { |host| host.current_state_observation.nil? },
        segments: segments,
        observed_mappings: @catalog ? [] : observed_mappings(fresh),
        stale_observed_mappings: @catalog ? [] : observed_mappings(stale, stale: true)
      }
    }
  end

  private

  def cohort_hosts
    @hosts.partition do |host|
      observation = host.current_state_observation
      observation && !observation.stale? && identity(observation) == @policy_identity
    end.then do |fresh, remaining|
      [fresh, remaining.select { |host| (observation = host.current_state_observation) && observation.stale? && identity(observation) == @policy_identity }]
    end
  end

  def identity(observation)
    return observation.host.policy_identity_for(observation) if observation.respond_to?(:host)

    observation.host_snapshot.details.dig("selinux", "policy_identity")
  end

  def inventory(host)
    host.current_state_observation.host_snapshot.details.dig("selinux", "policy", "port_inventory") || { "status" => "unknown", "mappings" => [] }
  end

  def catalog_data
    return { available: false, completeness: {}, mappings: [] } unless @catalog

    @catalog.slice("policy_identity", "version", "provenance", "reference_source", "content_digest", "loaded_policy_digest", "distribution_catalog_revision_id", "completeness", "mappings").merge("available" => true)
  end

  def compare(host)
    return [] unless @catalog

    state = inventory(host)
    PortCatalogComparison.call(catalog_mappings: catalog_mappings, catalog_completeness: @catalog.fetch("completeness"), inventory_status: state["status"], observed_mappings: host_mappings(state)).map do |segment|
      segment.merge(host_id: host.id, hostname: host.hostname)
    end
  end

  def observed_mappings(hosts, stale: false)
    hosts.flat_map do |host|
      state = inventory(host)
      next [] unless %w[observed partial].include?(state["status"])

      host_mappings(state).map do |mapping|
        mapping.merge(inventory_status: stale ? "stale" : state["status"], host_id: host.id, hostname: host.hostname)
      end
    end
  end

  def catalog_mappings
    Array(@catalog&.fetch("mappings")).map { |mapping| mapping.symbolize_keys }
  end

  def host_mappings(state)
    Array(state["mappings"]).flat_map do |mapping|
      Array(mapping["ports"]).map { |range| { protocol: mapping["protocol"], type: mapping["type"], start: range["start"], end: range["end"], provenance: range["provenance"] } }
    end
  end

end
