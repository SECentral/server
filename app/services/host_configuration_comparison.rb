class HostConfigurationComparison
  def self.call(host)
    new(host).call
  end

  def initialize(host)
    @host = host
  end

  attr_reader :observation, :snapshot, :stale, :selinux, :policy_identity, :reference, :catalog_revision
  attr_reader :boolean_overlay, :port_overlay
  attr_reader :boolean_rows, :boolean_differences, :boolean_matches, :boolean_host_only_rows
  attr_reader :boolean_reference_only_rows, :boolean_unavailable_rows, :boolean_reference_entries
  attr_reader :port_segments, :port_difference_segments, :port_limitation_segments

  def call
    @observation = @host.current_state_observation
    @snapshot = @observation&.host_snapshot
    @selinux = @snapshot&.details&.fetch("selinux", {}) || {}
    @policy_identity = @host.policy_identity_for(@observation)
    @selinux = @selinux.merge("policy_identity" => @policy_identity, "enforcement" => @host.enforcement_for(@observation))
    @selinux = @selinux.merge("policy" => @selinux.fetch("policy", {}).merge("port_inventory" => @host.port_inventory_for(@observation)))
    @reference = DistributionCatalogReference.for_snapshot(@snapshot) if @policy_identity
    @catalog_revision = @reference&.revision
    @stale = @observation&.stale?
    return self unless policy_identity_matches?

    run_comparison
    self
  end

  def comparison_available?
    boolean_reference_available? || port_reference_available?
  end

  def boolean_reference_available?
    boolean_overlay&.dig(:catalog, "available") || boolean_overlay&.dig(:catalog, :available)
  end

  def port_reference_available?
    port_overlay&.dig(:catalog, "available") || port_overlay&.dig(:catalog, :available)
  end

  def boolean_summary
    return nil unless boolean_overlay

    {
      match: boolean_matches.size,
      differ: boolean_differences.size,
      host_only: boolean_host_only_rows.size,
      not_observed: (boolean_reference_only_rows.size + boolean_unavailable_rows.size),
      not_observed_label: boolean_unavailable_rows.any? ? "Unavailable" : "Not observed"
    }
  end

  def port_summary
    return nil unless port_overlay

    matching = port_segments.count { |segment| segment[:relation] == "matching_effective_type" }
    {
      match: matching,
      differ: port_difference_segments.size,
      not_observed: port_limitation_segments.size
    }
  end

  def inventory_status
    @selinux["boolean_status"] || @selinux.dig("policy", "port_inventory", "status") || "unknown"
  end

  private

  def policy_identity_matches?
    @policy_identity.to_s.match?(/\Asha256:[0-9a-f]{64}\z/)
  end

  def run_comparison
    boolean_catalog = @reference&.boolean_catalog || BooleanCatalog.for(@policy_identity)
    @boolean_overlay = BooleanCatalogOverlay.call(hosts: [@host], policy_identity: @policy_identity, catalog: boolean_catalog)

    port_catalog = @reference&.port_catalog || PortCatalog.for(@policy_identity)
    @port_overlay = PortCatalogOverlay.call(hosts: [@host], policy_identity: @policy_identity, catalog: port_catalog)

    observed_boolean_names = Array(@selinux["booleans"]).filter_map { |b| b["name"] }
    @boolean_rows = @boolean_overlay.dig(:observed, :rows) || []
    @boolean_differences = @boolean_rows.select { |row| row.dig(:counts, "reference_difference").positive? }
    @boolean_matches = @boolean_rows.select { |row| row.dig(:counts, "reference_match").positive? }
    @boolean_host_only_rows = @boolean_rows.reject { |row| row[:catalog] }.select { |row| (row.dig(:counts, "on") + row.dig(:counts, "off")).positive? }
    @boolean_reference_only_rows = @boolean_rows.select { |row| row[:catalog] && row.dig(:counts, "unknown").positive? && row.dig(:counts, "unavailable").zero? && row.dig(:counts, "stale").zero? && !observed_boolean_names.include?(row[:name]) }
    @boolean_unavailable_rows = @boolean_rows.select { |row| row.dig(:counts, "unavailable").positive? }
    @boolean_reference_entries = @boolean_rows.count { |row| row[:catalog] }

    @port_segments = @port_overlay.dig(:observed, :segments) || []
    @port_difference_segments = @port_segments.reject { |segment| %w[matching_effective_type comparison_unknown].include?(segment[:relation]) }
    @port_limitation_segments = @port_segments.select { |segment| segment[:relation] == "comparison_unknown" }
  end
end
