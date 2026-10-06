class AddFileContextChangeEvidence < ActiveRecord::Migration[8.1]
  def change
    add_column :raw_events, :file_context_changes, :jsonb, null: false, default: []
  end
end
