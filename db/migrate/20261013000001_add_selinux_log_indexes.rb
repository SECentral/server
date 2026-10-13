class AddSelinuxLogIndexes < ActiveRecord::Migration[8.1]
  def change
    add_index :raw_events, [:organization_id, :category, :audit_timestamp, :id], name: "index_raw_events_on_log_time"
    add_index :raw_events, [:organization_id, :host_id, :category, :audit_timestamp, :id], name: "index_raw_events_on_host_log_time"
  end
end
