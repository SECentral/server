class ResolutionIntentChange < ApplicationRecord
  belongs_to :issue
  belongs_to :issue_signature, optional: true
  validates :operator, presence: true
  validates :action, inclusion: { in: %w[selected changed cleared] }
end
