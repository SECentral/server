class HostConfigurationComparison
  def self.call(host, reference_revision_id: nil)
    new(host, reference_revision_id).call
  end

  def initialize(host, reference_revision_id = nil)
    @host = host
    @reference_revision_id = reference_revision_id
  end

  attr_reader :observation, :snapshot, :stale, :selinux, :policy_identity, :reference, :catalog_revision
  attr_reader :selection
  attr_reader :boolean_overlay, :port_overlay
  attr_reader :boolean_rows, :boolean_differences, :boolean_matches, :boolean_host_only_rows
  attr_reader :boolean_reference_only_rows, :boolean_unavailable_rows, :boolean_reference_entries
  attr_reader :port_segments, :port_difference_segments, :port_limitation_segments
  attr_reader :host_permissive_state, :effective_permissive_domains

  def call
    @observation = @host.current_state_observation
    @snapshot = @observation&.host_snapshot
    @selinux = @host.selinux_state_for(@observation)
    @policy_identity = @selinux["policy_identity"]
    @stale = @observation&.stale?
    @selection = CatalogReferenceSelection.call(snapshot: @snapshot, selinux: @selinux, revision_id: @reference_revision_id, stale: !!@stale)
    @reference = DistributionCatalogReference.from_revision(@selection.revision, applicability: @selection.applicability)
    @catalog_revision = @reference&.revision
    compare_effective_permissive_domains
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

  def compare_effective_permissive_domains
    @host_permissive_state = PolicyPermissiveDomains.lookup(@policy_identity)
    reference_state = if @catalog_revision && @selection.family(CatalogReferenceSelection::EFFECTIVE_FAMILY)[:reason].nil?
      @catalog_revision.reference_permissive_domains
    else
      { status: "unavailable", domains: nil }
    end
    @selection = @selection.with_effective_permissive_states(host_state: @host_permissive_state, reference_state: reference_state)
    family = @selection.family(CatalogReferenceSelection::EFFECTIVE_FAMILY)
    observed = family[:comparison_allowed]
    host_set = @host_permissive_state[:domains]
    reference_set = reference_state[:domains]
    sets = observed ? {
      matching: (host_set & reference_set).uniq.sort,
      unexpected_on_host: (host_set - reference_set).uniq.sort,
      missing_from_host: (reference_set - host_set).uniq.sort
    } : { matching: nil, unexpected_on_host: nil, missing_from_host: nil }
    @effective_permissive_domains = sets.merge(status: observed ? "observed" : "unknown", reason: family[:reason],
      counts: observed ? sets.transform_values(&:size) : nil,
      host: permissive_evidence(@host_permissive_state).merge(snapshot_id: @snapshot&.id, observation_id: @observation&.id,
        evidence_basis: policy_identity_matches? && !@stale ? "trusted_current_checkpoint" : nil),
      reference: @catalog_revision && permissive_evidence(reference_state).merge(revision_id: @catalog_revision.id,
        content_digest: @catalog_revision.content_digest, policy_identity: @catalog_revision.loaded_policy_digest),
      selection: { mode: @selection.mode, basis: @selection.basis, policy_identity_match: @selection.policy_identity_match,
        equivalence_asserted: @selection.mode == "automatic" && @selection.basis == "exact_policy_identity" })
  end

  def permissive_evidence(state)
    { status: state[:status], policy_identity: state[:policy_identity],
      semantics_version: state[:status] == "observed" ? state[:semantics_version] : nil,
      evaluator_version: state[:evaluator_version], evaluated_at: state[:evaluated_at] }
  end

  def policy_identity_matches?
    @policy_identity.to_s.match?(/\Asha256:[0-9a-f]{64}\z/)
  end

  def run_comparison
    boolean_catalog = @reference&.boolean_catalog unless @selection.family("booleans")[:reason] == "incompatible_policy_context"
    @boolean_overlay = BooleanCatalogOverlay.call(hosts: [@host], policy_identity: @policy_identity, catalog: boolean_catalog)

    port_catalog = @reference&.port_catalog unless @selection.family("ports")[:reason] == "incompatible_policy_context"
    @port_overlay = PortCatalogOverlay.call(hosts: [@host], policy_identity: @policy_identity, catalog: port_catalog)

    observed_boolean_names = Array(@selinux["booleans"]).filter_map { |b| b["name"] }
    @boolean_rows = @boolean_overlay.dig(:observed, :rows) || []
    @boolean_differences = @boolean_rows.select { |row| row.dig(:counts, "reference_difference").positive? }
    @boolean_matches = @boolean_rows.select { |row| row.dig(:counts, "reference_match").positive? }
    @boolean_host_only_rows = boolean_reference_available? ? @boolean_rows.reject { |row| row[:catalog] }.select { |row| (row.dig(:counts, "on") + row.dig(:counts, "off")).positive? } : []
    @boolean_reference_only_rows = @boolean_rows.select { |row| row[:catalog] && row.dig(:counts, "unknown").positive? && row.dig(:counts, "unavailable").zero? && row.dig(:counts, "stale").zero? && !observed_boolean_names.include?(row[:name]) }
    @boolean_unavailable_rows = @boolean_rows.select { |row| row.dig(:counts, "unavailable").positive? }
    @boolean_reference_entries = @boolean_rows.count { |row| row[:catalog] }

    @port_segments = @port_overlay.dig(:observed, :segments) || []
    @port_difference_segments = @port_segments.reject { |segment| %w[matching_effective_type comparison_unknown].include?(segment[:relation]) }
    @port_limitation_segments = @port_segments.select { |segment| segment[:relation] == "comparison_unknown" }
  end
end
