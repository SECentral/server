class CreatePolicyArtifactsAndFacts < ActiveRecord::Migration[8.1]
  def change
    create_table :policy_artifacts do |t|
      t.string :policy_identity, null: false
      t.binary :artifact, null: false
      t.bigint :artifact_size, null: false
      t.string :source_host_id
      t.timestamps
    end
    add_index :policy_artifacts, :policy_identity, unique: true

    create_table :policy_facts do |t|
      t.string :policy_identity, null: false
      t.string :query_kind, null: false
      t.string :source_type, null: false
      t.string :target_type, null: false
      t.string :object_class, null: false
      t.string :permission, null: false
      t.string :status, null: false, default: "pending"
      t.jsonb :matching_rules, null: false, default: []
      t.jsonb :rule_details, null: false, default: []
      t.string :evaluator_version
      t.text :error_message
      t.datetime :evaluated_at
      t.datetime :last_enqueued_at
      t.timestamps
    end
    add_index :policy_facts,
      %i[policy_identity query_kind source_type target_type object_class permission],
      unique: true, name: "index_policy_facts_on_exact_question"
    add_index :policy_facts, %i[policy_identity status]
  end
end
