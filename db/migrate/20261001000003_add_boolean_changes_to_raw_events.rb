class AddBooleanChangesToRawEvents < ActiveRecord::Migration[8.1]
  def change
    add_column :raw_events, :boolean_changes, :jsonb, null: false, default: []
  end
end
