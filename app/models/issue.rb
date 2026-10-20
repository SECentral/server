class Issue < ApplicationRecord
  STATUSES = %w[open resolved ignored].freeze
  DISPOSITIONS = %w[unclassified under_investigation expected_harmless application_configuration labeling_configuration policy_required possible_policy_package_defect suspicious_behavior].freeze

  belongs_to :organization
  has_many :signatures, class_name: "IssueSignature", dependent: :delete_all
  has_many :occurrences, dependent: :restrict_with_exception
  has_many :disposition_changes, class_name: "IssueDispositionChange", dependent: :restrict_with_exception

  validates :fingerprint_version, :fingerprint_digest, :source_type, :target_type,
    :target_class, :first_seen_at, :last_seen_at, presence: true
  validates :status, inclusion: { in: STATUSES }
  validates :disposition, inclusion: { in: DISPOSITIONS + ["mixed"] }

  def occurrences_count
    occurrences.count
  end

  def set_disposition!(new_disposition, note: nil, signature_ids: signatures.ids)
    raise ArgumentError, "invalid issue disposition" unless DISPOSITIONS.include?(new_disposition)

    with_lock do
      reviewed_signatures(signature_ids).each { |signature| signature.set_disposition!(new_disposition, note: note) }
      refresh_from_signatures!
    end
  end

  def transition_to!(new_status, signature_ids: signatures.ids)
    raise ArgumentError, "invalid issue status" unless STATUSES.include?(new_status)

    with_lock do
      reviewed_signatures(signature_ids).each { |signature| signature.transition_to!(new_status) }
      refresh_from_signatures!
    end
  end

  def refresh_from_signatures!
    items = signatures.reload.to_a
    return if items.empty?

    state = items.any? { |item| item.status == "open" } ? "open" : items.all? { |item| item.status == "ignored" } ? "ignored" : "resolved"
    reopened = state == "open" && status != "open"
    update!(status: state, disposition: items.map(&:disposition).uniq.one? ? items.first.disposition : "mixed",
      permissions: items.flat_map(&:permissions).uniq.sort,
      first_seen_at: items.map(&:first_seen_at).min, last_seen_at: items.map(&:last_seen_at).max,
      resolved_at: state == "resolved" ? items.filter_map(&:resolved_at).max : resolved_at,
      ignored_at: state == "ignored" ? items.filter_map(&:ignored_at).max : ignored_at,
      reopened_at: reopened ? Time.current : reopened_at,
      regressions_count: regressions_count + (reopened ? 1 : 0))
  end

  def reviewed_signatures(ids)
    raise ArgumentError, "Select at least one reviewed signature" unless ids.is_a?(Array) && ids.any? && ids.all? { |id| id.is_a?(Integer) && id.positive? }

    selected = signatures.where(id: ids.uniq).to_a
    raise ArgumentError, "Signature does not belong to this issue" unless selected.size == ids.uniq.size

    selected
  end

  def display_status
    status == "open" && reopened_at.present? && (resolved_at.nil? || reopened_at > resolved_at) ? "regressed" : status
  end
end
