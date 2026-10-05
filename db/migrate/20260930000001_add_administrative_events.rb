class AddAdministrativeEvents < ActiveRecord::Migration[8.1]
  def change
    add_column :raw_events, :category, :string, null: false, default: "avc"
    add_column :raw_events, :transition_type, :string
    add_index :raw_events, [ :host_id, :boot_id, :transition_type, :audit_timestamp ], name: "index_raw_events_on_state_transition"
  end
end
