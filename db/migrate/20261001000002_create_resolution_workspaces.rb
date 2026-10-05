class CreateResolutionWorkspaces < ActiveRecord::Migration[8.1]
  def change
    create_table :resolution_intents do |t|
      t.references :issue, null: false, foreign_key: true, index: { unique: true }
      t.string :candidate_id, null: false
      t.string :candidate_kind, null: false
      t.text :selected_intent, null: false
      t.string :operator, null: false
      t.datetime :selected_at, null: false
      t.string :status, null: false, default: "selected"
      t.string :evidence_version, null: false
      t.jsonb :evidence_basis, null: false, default: {}
      t.jsonb :plan_snapshot, null: false, default: {}
      t.timestamps
    end
    create_table :resolution_intent_changes do |t|
      t.references :issue, null: false, foreign_key: true
      t.string :operator, null: false
      t.string :action, null: false
      t.jsonb :details, null: false, default: {}
      t.timestamps
    end
    create_table :policy_drafts do |t|
      t.references :organization, null: false, foreign_key: true
      t.string :name, null: false
      t.string :operator, null: false
      t.string :status, null: false, default: "draft"
      t.timestamps
    end
    create_table :policy_draft_entries do |t|
      t.references :policy_draft, null: false, foreign_key: true
      t.string :source_type, null: false
      t.string :target_type, null: false
      t.string :object_class, null: false
      t.string :permission, null: false
      t.jsonb :provenance, null: false, default: []
      t.timestamps
      t.index [:policy_draft_id, :source_type, :target_type, :object_class, :permission], unique: true, name: "index_draft_entries_on_permission"
    end
  end
end
