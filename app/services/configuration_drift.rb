class ConfigurationDrift
  FAMILIES = %w[file_contexts modules policy_identity].freeze

  def self.call(host)
    new(host).call
  end

  def initialize(host)
    @host = host
  end

  def call
    @host.host_snapshot_observations.includes(:host_snapshot).reorder(:first_received_at, :id).to_a.each_cons(2).flat_map do |before, after|
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

    reasons = uncertainty_reasons(before, after)
    evidence = { family: family, direction: reasons.empty? ? "ordered" : "unknown",
                 epochs: [epoch_evidence(before), epoch_evidence(after)] }
    return evidence.merge(reasons: reasons, values_differ: true) if reasons.any?

    if added.empty? && removed.empty? && changed.any? && changed.all? { |key| without_provenance(old[key]) == without_provenance(new[key]) }
      return evidence.merge(baseline: true, from: timestamp(before.last_observed_at), to: timestamp(after.first_observed_at),
               added_count: 0, removed_count: 0, changed_count: 0, added: [], removed: [], changed: [])
    end

    return evidence.merge(baseline: true, from: timestamp(before.last_observed_at), to: timestamp(after.first_observed_at),
             added_count: added.size, removed_count: removed.size, changed_count: changed.size,
             added: [], removed: [], changed: []) if old.empty? && new.any?

    evidence.merge(from: timestamp(before.last_observed_at), to: timestamp(after.first_observed_at),
      added: added.map { |key| new[key] }, removed: removed.map { |key| old[key] },
      changed: changed.map { |key| { key: key, before: old[key], after: new[key] } })
  end

  def uncertainty_reasons(before, after)
    boots = [before, after].map { |observation| observation.host_snapshot.details["boot_id"] }
    reasons = []
    reasons << "unknown_boot_id" unless boots.all? { |boot| boot.is_a?(String) && boot.present? }
    reasons << "different_boot_ids" if reasons.empty? && boots.first != boots.last
    reasons << "invalid_observed_bounds" if [before, after].any? { |o| o.first_observed_at > o.last_observed_at }
    reasons << "invalid_receipt_bounds" if [before, after].any? { |o| o.first_received_at > o.last_received_at }
    reasons << "overlapping_observed_bounds" if before.last_observed_at >= after.first_observed_at
    reasons
  end

  def epoch_evidence(observation)
    boot = observation.host_snapshot.details["boot_id"]
    { observation_id: observation.id, snapshot_id: observation.host_snapshot_id,
      boot_id: boot.is_a?(String) && boot.present? ? boot : nil,
      first_observed_at: timestamp(observation.first_observed_at), last_observed_at: timestamp(observation.last_observed_at),
      first_received_at: timestamp(observation.first_received_at), last_received_at: timestamp(observation.last_received_at) }
  end

  def timestamp(value)
    value.utc.iso8601(6)
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
