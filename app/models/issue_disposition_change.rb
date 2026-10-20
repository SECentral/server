class IssueDispositionChange < ApplicationRecord
  belongs_to :issue
  belongs_to :issue_signature, optional: true

  validates :previous_disposition, :disposition, presence: true
  validates :note, length: { maximum: 2_000 }, allow_nil: true
end
