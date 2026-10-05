class Issue < ApplicationRecord
  STATUSES = %w[open resolved ignored].freeze
  DISPOSITIONS = %w[unclassified under_investigation expected_harmless application_configuration labeling_configuration policy_required possible_policy_package_defect suspicious_behavior].freeze

  belongs_to :organization
  has_many :occurrences, dependent: :restrict_with_exception
  has_many :disposition_changes, class_name: "IssueDispositionChange", dependent: :restrict_with_exception

  validates :fingerprint_version, :fingerprint_digest, :source_type, :target_type,
    :target_class, :first_seen_at, :last_seen_at, presence: true
  validates :status, inclusion: { in: STATUSES }
  validates :disposition, inclusion: { in: DISPOSITIONS }

  def occurrences_count
    occurrences.count
  end

  def set_disposition!(new_disposition, note: nil)
    raise ArgumentError, "invalid issue disposition" unless DISPOSITIONS.include?(new_disposition)

    with_lock do
      previous = disposition
      update!(disposition: new_disposition)
      disposition_changes.create!(previous_disposition: previous, disposition: new_disposition, note: note.presence, created_at: Time.current) if previous != new_disposition || note.present?
    end
  end

  def transition_to!(new_status)
    raise ArgumentError, "invalid issue status" unless STATUSES.include?(new_status)

    now = Time.current
    self.status = new_status
    self.resolved_at = new_status == "resolved" ? now : resolved_at
    self.ignored_at = new_status == "ignored" ? now : ignored_at
    save!
  end

  def display_status
    reopened_at.present? && (resolved_at.nil? || reopened_at > resolved_at) ? "regressed" : status
  end
end
