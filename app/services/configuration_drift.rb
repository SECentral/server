class ConfigurationDrift
  FAMILIES = %w[file_contexts modules policy_identity].freeze

  def self.call(host)
    new(host).call
  end

  def initialize(host)
    @host = host
  end

  def call
    @host.host_snapshot_observations.includes(:host_snapshot).order(:first_received_at, :id).to_a.each_cons(2).flat_map do |before, after|
      FAMILIES.filter_map { |family| transition(family, before, after) }
    end
  end

  private

  def transition(family, before, after)
    old = family_values(family, before.host_snapshot.details)
    new = family_values(family, after.host_snapshot.details)
    added = new.keys - old.keys
    removed = old.keys - new.keys
    changed = (old.keys & new.keys).select { |key| old[key] != new[key] }
    return if added.empty? && removed.empty? && changed.empty?

    if added.empty? && removed.empty? && changed.any? && changed.all? { |key| without_provenance(old[key]) == without_provenance(new[key]) }
      return { family: family, baseline: true, from: before.last_observed_at, to: after.first_observed_at,
               added_count: 0, removed_count: 0, changed_count: 0, added: [], removed: [], changed: [] }
    end

    return { family: family, baseline: true, from: before.last_observed_at, to: after.first_observed_at,
             added_count: added.size, removed_count: removed.size, changed_count: changed.size,
             added: [], removed: [], changed: [] } if old.empty? && new.any?

    { family: family, from: before.last_observed_at, to: after.first_observed_at,
      added: added.map { |key| new[key] }, removed: removed.map { |key| old[key] },
      changed: changed.map { |key| { key: key, before: old[key], after: new[key] } } }
  end

  def family_values(family, details)
    case family
    when "file_contexts"
      Array(details.dig("selinux", "policy", "file_contexts")).to_h { |item| [item.values_at("pattern", "file_type"), item.slice("pattern", "file_type", "context", "provenance")] }
    when "modules"
      modules = Array(details.dig("selinux", "policy", "modules"))
      modules = Array(details.dig("selinux", "policy", "custom_modules")).map { |item| item.merge("provenance" => "unknown") } if modules.empty?
      modules.to_h { |item| [item.values_at("name", "priority"), item.slice("name", "priority", "version", "checksum", "provenance")] }
    when "policy_identity"
      { ["kernel_policy_version"] => details.dig("selinux", "kernel_policy_version"), ["package"] => details.dig("selinux", "policy", "package") }
    end
  end

  def without_provenance(value)
    value.is_a?(Hash) ? value.reject { |key, _| key == "provenance" } : value
  end
end
