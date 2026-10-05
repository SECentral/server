class PolicyDraft < ApplicationRecord
  belongs_to :organization
  has_many :policy_draft_entries, dependent: :destroy
  validates :name, length: { in: 1..100 }
  validates :operator, presence: true
  validates :status, inclusion: { in: %w[draft exported] }
end
