class PolicyDraftEntry < ApplicationRecord
  belongs_to :policy_draft
  validates :source_type, :target_type, :object_class, :permission, format: { with: /\A[A-Za-z][A-Za-z0-9_]*\z/ }
end
