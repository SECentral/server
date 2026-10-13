class AddHostReportingDuration < ActiveRecord::Migration[8.1]
  def change
    add_column :hosts, :reporting_started_at, :datetime, precision: 6
    add_column :hosts, :reporting_observed_at, :datetime, precision: 6
    add_column :hosts, :reporting_received_at, :datetime, precision: 6
    add_column :hosts, :reporting_boot_id, :string
    add_column :hosts, :reporting_sample_status, :string
    add_check_constraint :hosts, "reporting_sample_status IS NULL OR reporting_sample_status IN ('eligible', 'ineligible', 'timing_unknown', 'recovering')", name: "host_reporting_sample_status"

    create_table :host_reporting_days do |t|
      t.references :host, null: false, foreign_key: { on_delete: :cascade }, index: false
      t.date :observed_on, null: false
      t.bigint :credited_microseconds, null: false, default: 0
      t.timestamps
    end
    add_index :host_reporting_days, [:host_id, :observed_on], unique: true
    add_check_constraint :host_reporting_days, "credited_microseconds BETWEEN 0 AND 86400000000", name: "host_reporting_day_duration"
  end
end
