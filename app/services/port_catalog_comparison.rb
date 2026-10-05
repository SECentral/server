class PortCatalogComparison
  def self.call(catalog_mappings:, catalog_completeness:, inventory_status:, observed_mappings:)
    new(catalog_mappings, catalog_completeness, inventory_status, observed_mappings).call
  end

  def initialize(catalog_mappings, catalog_completeness, inventory_status, observed_mappings)
    @catalog_mappings = catalog_mappings
    @catalog_completeness = catalog_completeness
    @inventory_status = inventory_status
    @observed_mappings = observed_mappings
  end

  def call
    return [] if %w[unavailable unknown].include?(@inventory_status)

    (@catalog_mappings + @observed_mappings).map { |mapping| mapping[:protocol] }.uniq.flat_map do |protocol|
      compare_protocol(protocol)
    end
  end

  private

  def compare_protocol(protocol)
    catalog = @catalog_mappings.select { |mapping| mapping[:protocol] == protocol }
    observed = @observed_mappings.select { |mapping| mapping[:protocol] == protocol }
    boundaries = (catalog + observed).flat_map { |mapping| [mapping[:start].to_i, mapping[:end].to_i + 1] }.uniq.sort
    return [] if boundaries.size < 2

    merge_segments(boundaries.each_cons(2).filter_map do |start_port, after_end|
      finish = after_end - 1
      catalog_types = catalog.filter_map { |mapping| mapping[:type] if covers?(mapping, start_port, finish) }.uniq.sort
      host_ranges = observed.select { |mapping| covers?(mapping, start_port, finish) }
      observed_types = host_ranges.map { |mapping| mapping[:type] }.uniq.sort
      next if catalog_types.empty? && observed_types.empty?

      provenances = host_ranges.map { |mapping| mapping[:provenance] }.uniq
      local_classification = provenances.empty? ? nil : (provenances.include?("custom") ? "custom" : (provenances.size == 1 ? provenances.first : "unknown"))
      { protocol: protocol, start: start_port, end: finish, catalog_types: catalog_types, observed_types: observed_types, relation: relation_for(protocol, catalog_types, observed_types), local_classification: local_classification, inventory_status: @inventory_status }
    end)
  end

  def covers?(mapping, start_port, finish)
    mapping[:start].to_i <= start_port && mapping[:end].to_i >= finish
  end

  def relation_for(protocol, catalog_types, observed_types)
    return "matching_effective_type" if catalog_types.any? && observed_types.any? && catalog_types == observed_types
    return "different_effective_type" if catalog_types.any? && observed_types.any?
    return @inventory_status == "observed" ? "catalog_defined_not_observed" : "comparison_unknown" if catalog_types.any?

    @catalog_completeness[protocol] == "complete" ? "observed_not_represented" : "observed_not_represented_in_incomplete_catalog"
  end

  def merge_segments(segments)
    segments.each_with_object([]) do |segment, merged|
      previous = merged.last
      comparable = previous && previous[:end] + 1 == segment[:start] && previous.except(:start, :end) == segment.except(:start, :end)
      comparable ? previous[:end] = segment[:end] : merged << segment
    end
  end
end
