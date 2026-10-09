class CreateCatalogManagements < ActiveRecord::Migration[8.1]
  def up
    create_table :catalog_managements do |t|
      t.references :distribution_catalog_revision, null: false, index: { unique: true }, foreign_key: { on_delete: :cascade }
      t.string :display_name, null: false, limit: 120
      t.string :lifecycle, null: false, default: "active"
      t.timestamps
      t.index [:lifecycle, :distribution_catalog_revision_id]
      t.check_constraint "lifecycle IN ('active', 'archived')", name: "catalog_management_lifecycle"
      t.check_constraint "char_length(trim(display_name)) BETWEEN 1 AND 120", name: "catalog_management_name"
    end

    create_table :catalog_management_changes do |t|
      t.references :catalog_management, null: false, foreign_key: { on_delete: :cascade }
      t.string :changed_by, null: false
      t.string :previous_display_name, null: false
      t.string :display_name, null: false
      t.string :previous_lifecycle, null: false
      t.string :lifecycle, null: false
      t.datetime :created_at, null: false
    end

    # Backfill only management rows; never save an immutable revision or import.
    revisions = Class.new(ActiveRecord::Base) { self.table_name = "distribution_catalog_revisions" }
    managements = Class.new(ActiveRecord::Base) { self.table_name = "catalog_managements" }
    revisions.find_each do |revision|
      distribution = { "almalinux" => "AlmaLinux", "rhel" => "RHEL" }.fetch(revision.distribution, revision.distribution.titleize)
      managements.create!(distribution_catalog_revision_id: revision.id, display_name: [distribution, revision.major_version].compact.join(" "), lifecycle: "active")
    end
  end

  def down
    drop_table :catalog_management_changes
    drop_table :catalog_managements
  end
end
