class AddEnforcementTransitionEvidence < ActiveRecord::Migration[8.1]
  def change
    add_column :raw_events, :enforcement_changes, :jsonb, null: false, default: []
    add_column :raw_events, :checkpoint_invalidated_fields, :jsonb, null: false, default: []
  end
end
