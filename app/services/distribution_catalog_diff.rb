class DistributionCatalogDiff
  def self.call(left, right)
    new(left, right).call
  end

  def initialize(left, right)
    @left = left
    @right = right
  end

  def call
    {
      policy: {
        loaded_policy_digest_changed: @left.loaded_policy_digest != @right.loaded_policy_digest,
        packages_changed: @left.policy_packages != @right.policy_packages
      },
      booleans: boolean_diff,
      ports: port_diff
    }
  end

  private

  def boolean_diff
    left = @left.distribution_catalog_booleans.index_by(&:name)
    right = @right.distribution_catalog_booleans.index_by(&:name)
    shared = left.keys & right.keys
    {
      added: (right.keys - left.keys).sort,
      removed: (left.keys - right.keys).sort,
      default_changed: shared.select { |name| left[name].default_value != right[name].default_value }.sort,
      description_changed: shared.select { |name| left[name].description != right[name].description }.sort
    }
  end

  def port_diff
    left = @left.port_catalog_mappings
    right = @right.port_catalog_mappings
    left_ranges = left.group_by { |mapping| mapping.slice(:protocol, :start, :end) }
    right_ranges = right.group_by { |mapping| mapping.slice(:protocol, :start, :end) }
    {
      added: right - left,
      removed: left - right,
      changed: (left_ranges.keys & right_ranges.keys).filter_map do |range|
        left_types = left_ranges[range].map { |mapping| mapping[:type] }.sort
        right_types = right_ranges[range].map { |mapping| mapping[:type] }.sort
        range.merge(from_types: left_types, to_types: right_types) if left_types != right_types
      end
    }
  end
end
