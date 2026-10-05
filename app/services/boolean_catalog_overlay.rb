class BooleanCatalogOverlay
  def self.call(hosts:, policy_identity:, catalog: nil)
    new(hosts, policy_identity, catalog).call
  end

  def initialize(hosts, policy_identity, catalog)
    @hosts = hosts
    @policy_identity = policy_identity
    @catalog = catalog || BooleanCatalog.for(policy_identity)
  end

  def call
    fresh, stale = cohort_hosts
    names = (catalog_names + observed_names(fresh, stale)).uniq
    rows = names.map { |name| row(name, fresh, stale) }
    {
      cohort: @policy_identity,
      catalog: catalog_data,
      observed: {
        fresh_host_count: fresh.size,
        stale_host_count: stale.size,
        outside_cohort_host_count: @hosts.size - fresh.size - stale.size,
        no_current_configuration_host_count: @hosts.count { |host| host.current_state_observation.nil? },
        rows: rows,
        unmatched_observed_names: rows.reject { |row| row[:catalog] }.map { |row| row[:name] }
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

  def catalog_data
    return { available: false, completeness: "unavailable", entries: [] } unless @catalog

    @catalog.slice("policy_identity", "version", "provenance", "reference_source", "content_digest", "loaded_policy_digest", "distribution_catalog_revision_id").merge("available" => true, "completeness" => @catalog.fetch("complete") ? "complete" : "incomplete", "entries" => @catalog.fetch("booleans"))
  end

  def catalog_names
    Array(@catalog&.fetch("booleans")).filter_map { |entry| entry["name"] }
  end

  def observed_names(fresh, stale)
    (fresh + stale).flat_map { |host| Array(host.current_state_observation.host_snapshot.details.dig("selinux", "booleans")).filter_map { |boolean| boolean["name"] } }.uniq.sort
  end

  def row(name, fresh, stale)
    entry = Array(@catalog&.fetch("booleans")).find { |boolean| boolean["name"] == name }
    counts = %w[on off unknown unavailable stale runtime_default_divergence reference_match reference_difference].index_with { 0 }
    fresh.each { |host| count(counts, host, name, entry, boolean_state(host, name)) }
    stale.each { counts["stale"] += 1 }
    {
      name: name,
      catalog: entry,
      catalog_status: entry ? "defined" : (@catalog ? (@catalog.fetch("complete") ? "not_defined" : "not_represented") : "unavailable"),
      counts: counts
    }
  end

  def boolean_state(host, name)
    selinux = host.current_state_observation.host_snapshot.details.fetch("selinux", {})
    return :unavailable if selinux["boolean_status"] == "unavailable"

    boolean = Array(selinux["booleans"]).find { |entry| entry["name"] == name }
    return :unknown unless boolean && boolean["status"] == "observed" && boolean["current"].in?([true, false])

    boolean["current"] ? :on : :off
  end

  def count(counts, host, name, entry, state)
    counts[state.to_s] += 1
    return unless %i[on off].include?(state)

    boolean = host.current_state_observation.host_snapshot.details.dig("selinux", "booleans").find { |entry| entry["name"] == name }
    counts[boolean["current"] == entry["default"] ? "reference_match" : "reference_difference"] += 1 if entry
    reported_default = boolean.key?("default") ? boolean["default"] : boolean["persistent"]
    counts["runtime_default_divergence"] += 1 if reported_default.in?([true, false]) && reported_default != boolean["current"]
  end
end
