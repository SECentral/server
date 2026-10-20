class IssueSignature < ApplicationRecord
  belongs_to :issue
  has_many :occurrences, dependent: :restrict_with_exception
  has_many :disposition_changes, class_name: "IssueDispositionChange", dependent: :restrict_with_exception

  validates :fingerprint_version, :fingerprint_digest, :first_seen_at, :last_seen_at, presence: true
  validates :status, inclusion: { in: Issue::STATUSES }
  validates :disposition, inclusion: { in: Issue::DISPOSITIONS }

  def transition_to!(new_status)
    raise ArgumentError, "Unknown status" unless Issue::STATUSES.include?(new_status)

    update!(status: new_status, resolved_at: new_status == "resolved" ? Time.current : resolved_at,
      ignored_at: new_status == "ignored" ? Time.current : ignored_at)
  end

  def set_disposition!(value, note: nil)
    raise ArgumentError, "Unknown disposition" unless Issue::DISPOSITIONS.include?(value)

    previous = disposition
    update!(disposition: value)
    if previous != value || note.present?
      IssueDispositionChange.create!(issue: issue, issue_signature: self, previous_disposition: previous, disposition: value, note: note.presence)
    end
  end
end
