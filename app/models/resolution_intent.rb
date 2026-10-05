class ResolutionIntent < ApplicationRecord
  belongs_to :issue
  validates :candidate_id, :candidate_kind, :selected_intent, :operator, :selected_at, :evidence_version, presence: true
  validates :status, inclusion: { in: %w[selected cleared] }
  validates :semantic_plan_basis, presence: true, if: -> { status == "selected" }
  validates :plan_semantics_version, numericality: { only_integer: true, greater_than: 0 }, if: -> { status == "selected" }
end
