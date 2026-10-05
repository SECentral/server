class AddSemanticBasisToResolutionIntents < ActiveRecord::Migration[8.1]
  def change
    # NULL identifies legacy reviews: preserve them, but require explicit re-review.
    add_column :resolution_intents, :semantic_plan_basis, :jsonb
    add_column :resolution_intents, :plan_semantics_version, :integer
  end
end
