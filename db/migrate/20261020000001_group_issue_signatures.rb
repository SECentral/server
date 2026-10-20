require "digest"

class GroupIssueSignatures < ActiveRecord::Migration[8.1]
  def up
    create_table :issue_signatures do |t|
      t.references :issue, null: false, foreign_key: { on_delete: :cascade }
      t.integer :fingerprint_version, null: false
      t.string :fingerprint_digest, null: false
      t.jsonb :permissions, null: false, default: []
      t.string :status, null: false, default: "open"
      t.string :disposition, null: false, default: "unclassified"
      t.datetime :first_seen_at, null: false
      t.datetime :last_seen_at, null: false
      t.datetime :resolved_at
      t.datetime :ignored_at
      t.datetime :reopened_at
      t.integer :regressions_count, null: false, default: 0
      t.timestamps
    end
    add_index :issue_signatures, [:issue_id, :fingerprint_version, :fingerprint_digest], unique: true, name: "index_issue_signatures_on_fingerprint"
    %i[occurrences issue_disposition_changes resolution_intents resolution_intent_changes].each do |table|
      add_reference table, :issue_signature, foreign_key: true, index: table == :resolution_intents ? { unique: true } : true
    end
    remove_index :resolution_intents, :issue_id
    add_index :resolution_intents, :issue_id, unique: true, where: "issue_signature_id IS NULL"

    columns = %w[fingerprint_version fingerprint_digest permissions status disposition first_seen_at last_seen_at resolved_at ignored_at reopened_at regressions_count created_at updated_at]
    execute <<~SQL
      INSERT INTO issue_signatures (id, issue_id, #{columns.join(', ')})
      SELECT id, id, #{columns.join(', ')} FROM issues
    SQL
    execute "SELECT setval(pg_get_serial_sequence('issue_signatures', 'id'), COALESCE((SELECT MAX(id) FROM issue_signatures), 1), EXISTS(SELECT 1 FROM issue_signatures))"
    %i[occurrences issue_disposition_changes resolution_intents resolution_intent_changes].each do |table|
      execute "UPDATE #{table} SET issue_signature_id = issue_id"
    end

    groups = select_all("SELECT organization_id, source_type, target_type, target_class, array_agg(id ORDER BY id) AS ids FROM issues GROUP BY organization_id, source_type, target_type, target_class")
    groups.each do |group|
      ids = group.fetch("ids").delete("{}").split(",").map(&:to_i)
      parent = ids.first
      id_list = ids.join(",")
      %i[occurrences issue_disposition_changes resolution_intents resolution_intent_changes issue_signatures].each do |table|
        execute "UPDATE #{table} SET issue_id = #{parent} WHERE issue_id IN (#{id_list})"
      end
      execute <<~SQL
        UPDATE policy_draft_entries SET provenance = (
          SELECT jsonb_agg(CASE WHEN (item->>'issue_id')::bigint IN (#{id_list})
            THEN item || jsonb_build_object('issue_id', #{parent}, 'issue_signature_id', (item->>'issue_id')::bigint)
            ELSE item END ORDER BY ordinal)
          FROM jsonb_array_elements(provenance) WITH ORDINALITY AS evidence(item, ordinal)
        ) WHERE EXISTS (SELECT 1 FROM jsonb_array_elements(provenance) item WHERE (item->>'issue_id')::bigint IN (#{id_list}))
      SQL
      execute "DELETE FROM issues WHERE id IN (#{id_list}) AND id <> #{parent}"
      digest = Digest::SHA256.hexdigest(["v4", *group.values_at("source_type", "target_type", "target_class"), ""].join("\0").b)
      execute <<~SQL
        UPDATE issues SET fingerprint_version = 4, fingerprint_digest = #{quote(digest)},
          permissions = (SELECT COALESCE(jsonb_agg(DISTINCT permission ORDER BY permission), '[]') FROM issue_signatures s, jsonb_array_elements(s.permissions) permission WHERE s.issue_id = #{parent}),
          first_seen_at = (SELECT MIN(first_seen_at) FROM issue_signatures WHERE issue_id = #{parent}),
          last_seen_at = (SELECT MAX(last_seen_at) FROM issue_signatures WHERE issue_id = #{parent}),
          resolved_at = (SELECT MAX(resolved_at) FROM issue_signatures WHERE issue_id = #{parent}),
          ignored_at = (SELECT MAX(ignored_at) FROM issue_signatures WHERE issue_id = #{parent}),
          reopened_at = (SELECT MAX(reopened_at) FROM issue_signatures WHERE issue_id = #{parent}),
          regressions_count = (SELECT SUM(regressions_count) FROM issue_signatures WHERE issue_id = #{parent}),
          status = CASE WHEN EXISTS(SELECT 1 FROM issue_signatures WHERE issue_id = #{parent} AND status = 'open') THEN 'open'
            WHEN NOT EXISTS(SELECT 1 FROM issue_signatures WHERE issue_id = #{parent} AND status <> 'ignored') THEN 'ignored' ELSE 'resolved' END,
          disposition = (SELECT CASE WHEN COUNT(DISTINCT disposition) = 1 THEN MIN(disposition) ELSE 'mixed' END FROM issue_signatures WHERE issue_id = #{parent}),
          occurrences_count = (SELECT COUNT(*) FROM occurrences WHERE issue_id = #{parent})
        WHERE id = #{parent}
      SQL
    end
    add_index :issues, [:organization_id, :source_type, :target_type, :target_class], unique: true, name: "index_issues_on_relationship"
  end

  def down
    raise ActiveRecord::IrreversibleMigration, "Relationship consolidation preserves original identities in issue_signatures"
  end
end
