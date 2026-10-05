class IssueDispositionChange < ApplicationRecord
  belongs_to :issue

  validates :previous_disposition, :disposition, presence: true
  validates :note, length: { maximum: 2_000 }, allow_nil: true
end
