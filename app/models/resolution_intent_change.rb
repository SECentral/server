class ResolutionIntentChange < ApplicationRecord
  belongs_to :issue
  validates :operator, presence: true
  validates :action, inclusion: { in: %w[selected changed cleared] }
end
