class CreateCatalogPolicyArtifacts < ActiveRecord::Migration[8.1]
  def change
    create_table :catalog_policy_artifacts do |t|
      t.references :distribution_catalog_revision, null: false, foreign_key: true, index: { unique: true }
      t.references :policy_artifact, null: false, foreign_key: true
      t.string :source_kind, null: false
      t.string :acquisition_basis, null: false, limit: 500
      t.string :attached_by, limit: 120
      t.timestamps
    end
  end
end
