# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.1].define(version: 2026_10_09_000001) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "pg_catalog.plpgsql"

  create_table "agent_installations", force: :cascade do |t|
    t.string "agent_version"
    t.bigint "bound_host_id"
    t.datetime "created_at", null: false
    t.datetime "last_seen_at"
    t.string "name", null: false
    t.bigint "organization_id", null: false
    t.datetime "updated_at", null: false
    t.index ["bound_host_id"], name: "index_agent_installations_on_bound_host_id"
    t.index ["last_seen_at"], name: "index_agent_installations_on_last_seen_at"
    t.index ["organization_id"], name: "index_agent_installations_on_organization_id"
  end

  create_table "catalog_management_changes", force: :cascade do |t|
    t.bigint "catalog_management_id", null: false
    t.string "changed_by", null: false
    t.string "previous_display_name", null: false
    t.string "display_name", null: false
    t.string "previous_lifecycle", null: false
    t.string "lifecycle", null: false
    t.datetime "created_at", null: false
    t.index ["catalog_management_id"], name: "index_catalog_management_changes_on_catalog_management_id"
  end

  create_table "catalog_managements", force: :cascade do |t|
    t.bigint "distribution_catalog_revision_id", null: false
    t.string "display_name", limit: 120, null: false
    t.string "lifecycle", default: "active", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["distribution_catalog_revision_id"], name: "index_catalog_managements_on_distribution_catalog_revision_id", unique: true
    t.index ["lifecycle", "distribution_catalog_revision_id"], name: "idx_on_lifecycle_distribution_catalog_revision_id_f680ee211a"
    t.check_constraint "char_length(TRIM(BOTH FROM display_name)) >= 1 AND char_length(TRIM(BOTH FROM display_name)) <= 120", name: "catalog_management_name"
    t.check_constraint "lifecycle::text = ANY (ARRAY['active'::character varying, 'archived'::character varying]::text[])", name: "catalog_management_lifecycle"
  end

  create_table "distribution_catalog_booleans", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.boolean "default_value", null: false
    t.text "description", null: false
    t.bigint "distribution_catalog_revision_id", null: false
    t.string "name", null: false
    t.datetime "updated_at", null: false
    t.index ["distribution_catalog_revision_id", "name"], name: "index_distribution_catalog_booleans_on_revision_and_name", unique: true
    t.index ["distribution_catalog_revision_id"], name: "idx_on_distribution_catalog_revision_id_d0306ad656"
  end

  create_table "distribution_catalog_imports", force: :cascade do |t|
    t.jsonb "acquisition_metadata", default: {}, null: false
    t.binary "artifact", null: false
    t.datetime "created_at", null: false
    t.bigint "distribution_catalog_revision_id", null: false
    t.string "source_path"
    t.datetime "updated_at", null: false
    t.index ["distribution_catalog_revision_id"], name: "idx_on_distribution_catalog_revision_id_fd9fa95ad5"
  end

  create_table "distribution_catalog_ports", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.bigint "distribution_catalog_revision_id", null: false
    t.integer "end_port", null: false
    t.string "protocol", null: false
    t.string "selinux_type", null: false
    t.integer "start_port", null: false
    t.datetime "updated_at", null: false
    t.index ["distribution_catalog_revision_id", "protocol", "start_port", "end_port", "selinux_type"], name: "index_distribution_catalog_ports_on_revision_and_mapping", unique: true
    t.index ["distribution_catalog_revision_id"], name: "idx_on_distribution_catalog_revision_id_7ca5258b0e"
  end

  create_table "distribution_catalog_revisions", force: :cascade do |t|
    t.string "architecture", null: false
    t.boolean "booleans_complete", null: false
    t.integer "collector_semantics_version", null: false
    t.string "content_digest", null: false
    t.datetime "created_at", null: false
    t.string "distribution", null: false
    t.integer "kernel_policy_version", null: false
    t.string "loaded_policy_digest", null: false
    t.string "major_version", null: false
    t.jsonb "policy_packages", default: [], null: false
    t.string "policy_type", null: false
    t.boolean "ports_complete", null: false
    t.integer "schema_version", null: false
    t.datetime "updated_at", null: false
    t.index ["content_digest"], name: "index_distribution_catalog_revisions_on_content_digest", unique: true
    t.index ["loaded_policy_digest"], name: "index_distribution_catalog_revisions_on_loaded_policy_digest", unique: true
  end

  create_table "host_snapshot_observations", force: :cascade do |t|
    t.bigint "agent_installation_id", null: false
    t.datetime "created_at", null: false
    t.datetime "first_observed_at", null: false
    t.datetime "first_received_at", null: false
    t.bigint "host_id", null: false
    t.bigint "host_snapshot_id", null: false
    t.datetime "last_observed_at", null: false
    t.datetime "last_received_at", null: false
    t.datetime "updated_at", null: false
    t.index ["agent_installation_id"], name: "index_host_snapshot_observations_on_agent_installation_id"
    t.index ["host_id", "last_received_at"], name: "idx_on_host_id_last_received_at_fdf557b153"
    t.index ["host_id"], name: "index_host_snapshot_observations_on_host_id"
    t.index ["host_snapshot_id"], name: "index_host_snapshot_observations_on_host_snapshot_id"
  end

  create_table "host_snapshots", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.jsonb "details", default: {}, null: false
    t.bigint "host_id", null: false
    t.datetime "updated_at", null: false
    t.index ["host_id"], name: "index_host_snapshots_on_host_id"
  end

  create_table "hosts", force: :cascade do |t|
    t.string "boot_id"
    t.datetime "created_at", null: false
    t.string "external_id", null: false
    t.string "hostname"
    t.datetime "last_seen_at"
    t.bigint "organization_id", null: false
    t.datetime "updated_at", null: false
    t.index ["last_seen_at"], name: "index_hosts_on_last_seen_at"
    t.index ["organization_id", "external_id"], name: "index_hosts_on_organization_id_and_external_id", unique: true
    t.index ["organization_id"], name: "index_hosts_on_organization_id"
  end

  create_table "issue_disposition_changes", force: :cascade do |t|
    t.string "changed_by"
    t.datetime "created_at", null: false
    t.string "disposition", null: false
    t.bigint "issue_id", null: false
    t.text "note"
    t.string "previous_disposition", null: false
    t.index ["issue_id", "created_at"], name: "index_issue_disposition_changes_on_issue_id_and_created_at"
    t.index ["issue_id"], name: "index_issue_disposition_changes_on_issue_id"
  end

  create_table "issues", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "disposition", default: "unclassified", null: false
    t.string "fingerprint_digest", null: false
    t.integer "fingerprint_version", null: false
    t.datetime "first_seen_at", null: false
    t.datetime "ignored_at"
    t.datetime "last_seen_at", null: false
    t.integer "occurrences_count", default: 0, null: false
    t.bigint "organization_id", null: false
    t.jsonb "permissions", default: [], null: false
    t.integer "regressions_count", default: 0, null: false
    t.datetime "reopened_at"
    t.datetime "resolved_at"
    t.string "source_type", null: false
    t.string "status", default: "open", null: false
    t.string "target_class", null: false
    t.string "target_type", null: false
    t.datetime "updated_at", null: false
    t.index ["disposition"], name: "index_issues_on_disposition"
    t.index ["organization_id", "fingerprint_version", "fingerprint_digest"], name: "index_issues_on_fingerprint", unique: true
    t.index ["organization_id"], name: "index_issues_on_organization_id"
    t.index ["status"], name: "index_issues_on_status"
  end

  create_table "normalized_denials", force: :cascade do |t|
    t.string "command"
    t.datetime "created_at", null: false
    t.jsonb "details", default: {}, null: false
    t.string "executable"
    t.integer "normalization_version", null: false
    t.integer "ordinal", null: false
    t.jsonb "permissions", default: [], null: false
    t.bigint "raw_event_id", null: false
    t.string "source_context"
    t.string "source_type"
    t.string "status", null: false
    t.string "target_class"
    t.string "target_context"
    t.jsonb "target_paths", default: [], null: false
    t.string "target_type"
    t.datetime "updated_at", null: false
    t.index ["raw_event_id", "normalization_version", "ordinal"], name: "index_normalized_denials_on_identity", unique: true
    t.index ["raw_event_id"], name: "index_normalized_denials_on_raw_event_id"
  end

  create_table "occurrences", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.bigint "host_id", null: false
    t.bigint "host_snapshot_id"
    t.bigint "issue_id"
    t.bigint "normalized_denial_id", null: false
    t.datetime "occurred_at", null: false
    t.bigint "organization_id", null: false
    t.bigint "raw_event_id", null: false
    t.datetime "updated_at", null: false
    t.index ["host_id"], name: "index_occurrences_on_host_id"
    t.index ["host_snapshot_id"], name: "index_occurrences_on_host_snapshot_id"
    t.index ["issue_id"], name: "index_occurrences_on_issue_id"
    t.index ["normalized_denial_id"], name: "index_occurrences_on_normalized_denial_id", unique: true
    t.index ["organization_id"], name: "index_occurrences_on_organization_id"
    t.index ["raw_event_id"], name: "index_occurrences_on_raw_event_id"
  end

  create_table "organizations", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "name", null: false
    t.datetime "updated_at", null: false
    t.index ["name"], name: "index_organizations_on_name", unique: true
  end

  create_table "policy_artifacts", force: :cascade do |t|
    t.binary "artifact", null: false
    t.bigint "artifact_size", null: false
    t.datetime "created_at", null: false
    t.string "policy_identity", null: false
    t.string "source_host_id"
    t.datetime "updated_at", null: false
    t.jsonb "permissive_domain_analysis", default: {}, null: false
    t.index ["policy_identity"], name: "index_policy_artifacts_on_policy_identity", unique: true
  end

  create_table "policy_draft_entries", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "object_class", null: false
    t.string "permission", null: false
    t.bigint "policy_draft_id", null: false
    t.jsonb "provenance", default: [], null: false
    t.string "source_type", null: false
    t.string "target_type", null: false
    t.datetime "updated_at", null: false
    t.index ["policy_draft_id", "source_type", "target_type", "object_class", "permission"], name: "index_draft_entries_on_permission", unique: true
    t.index ["policy_draft_id"], name: "index_policy_draft_entries_on_policy_draft_id"
  end

  create_table "policy_drafts", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "name", null: false
    t.string "operator", null: false
    t.bigint "organization_id", null: false
    t.string "status", default: "draft", null: false
    t.datetime "updated_at", null: false
    t.index ["organization_id"], name: "index_policy_drafts_on_organization_id"
  end

  create_table "policy_facts", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.text "error_message"
    t.datetime "evaluated_at"
    t.string "evaluator_version"
    t.datetime "last_enqueued_at"
    t.jsonb "matching_rules", default: [], null: false
    t.string "object_class", null: false
    t.string "permission", null: false
    t.string "policy_identity", null: false
    t.string "query_kind", null: false
    t.jsonb "rule_details", default: [], null: false
    t.string "source_type", null: false
    t.string "status", default: "pending", null: false
    t.string "target_type", null: false
    t.datetime "updated_at", null: false
    t.index ["policy_identity", "query_kind", "source_type", "target_type", "object_class", "permission"], name: "index_policy_facts_on_exact_question", unique: true
    t.index ["policy_identity", "status"], name: "index_policy_facts_on_policy_identity_and_status"
  end

  create_table "raw_audit_records", force: :cascade do |t|
    t.datetime "audit_timestamp", null: false
    t.datetime "created_at", null: false
    t.binary "payload", null: false
    t.integer "position", null: false
    t.bigint "raw_event_id", null: false
    t.integer "record_type", null: false
    t.bigint "sequence", null: false
    t.string "type_name", null: false
    t.datetime "updated_at", null: false
    t.index ["raw_event_id", "position"], name: "index_raw_audit_records_on_raw_event_id_and_position", unique: true
    t.index ["raw_event_id"], name: "index_raw_audit_records_on_raw_event_id"
  end

  create_table "raw_events", force: :cascade do |t|
    t.bigint "agent_installation_id", null: false
    t.datetime "agent_received_at", null: false
    t.bigint "audit_sequence", null: false
    t.datetime "audit_timestamp", null: false
    t.jsonb "boolean_changes", default: [], null: false
    t.string "boot_id", null: false
    t.string "category", default: "avc", null: false
    t.jsonb "checkpoint_invalidated_fields", default: [], null: false
    t.string "completion_reason", null: false
    t.datetime "created_at", null: false
    t.jsonb "enforcement_changes", default: [], null: false
    t.string "evidence_digest", null: false
    t.jsonb "file_context_changes", default: [], null: false
    t.jsonb "file_context_observations", default: [], null: false
    t.bigint "host_id", null: false
    t.datetime "host_observed_at"
    t.bigint "host_snapshot_id"
    t.bigint "organization_id", null: false
    t.jsonb "policy_evaluations", default: [], null: false
    t.jsonb "port_changes", default: [], null: false
    t.integer "schema_version", null: false
    t.datetime "server_received_at", null: false
    t.string "transition_type"
    t.datetime "updated_at", null: false
    t.index ["agent_installation_id"], name: "index_raw_events_on_agent_installation_id"
    t.index ["evidence_digest"], name: "index_raw_events_on_evidence_digest"
    t.index ["host_id", "boot_id", "transition_type", "audit_timestamp"], name: "index_raw_events_on_state_transition"
    t.index ["host_id"], name: "index_raw_events_on_host_id"
    t.index ["host_snapshot_id"], name: "index_raw_events_on_host_snapshot_id"
    t.index ["organization_id", "host_id", "boot_id", "audit_timestamp", "audit_sequence"], name: "index_raw_events_on_identity", unique: true
    t.index ["organization_id"], name: "index_raw_events_on_organization_id"
  end

  create_table "resolution_intent_changes", force: :cascade do |t|
    t.string "action", null: false
    t.datetime "created_at", null: false
    t.jsonb "details", default: {}, null: false
    t.bigint "issue_id", null: false
    t.string "operator", null: false
    t.datetime "updated_at", null: false
    t.index ["issue_id"], name: "index_resolution_intent_changes_on_issue_id"
  end

  create_table "resolution_intents", force: :cascade do |t|
    t.string "candidate_id", null: false
    t.string "candidate_kind", null: false
    t.datetime "created_at", null: false
    t.jsonb "evidence_basis", default: {}, null: false
    t.string "evidence_version", null: false
    t.bigint "issue_id", null: false
    t.string "operator", null: false
    t.integer "plan_semantics_version"
    t.jsonb "plan_snapshot", default: {}, null: false
    t.datetime "selected_at", null: false
    t.text "selected_intent", null: false
    t.jsonb "semantic_plan_basis"
    t.string "status", default: "selected", null: false
    t.datetime "updated_at", null: false
    t.index ["issue_id"], name: "index_resolution_intents_on_issue_id", unique: true
  end

  add_foreign_key "agent_installations", "hosts", column: "bound_host_id"
  add_foreign_key "agent_installations", "organizations"
  add_foreign_key "catalog_management_changes", "catalog_managements", on_delete: :cascade
  add_foreign_key "catalog_managements", "distribution_catalog_revisions", on_delete: :cascade
  add_foreign_key "distribution_catalog_booleans", "distribution_catalog_revisions"
  add_foreign_key "distribution_catalog_imports", "distribution_catalog_revisions"
  add_foreign_key "distribution_catalog_ports", "distribution_catalog_revisions"
  add_foreign_key "host_snapshot_observations", "agent_installations"
  add_foreign_key "host_snapshot_observations", "host_snapshots"
  add_foreign_key "host_snapshot_observations", "hosts"
  add_foreign_key "host_snapshots", "hosts"
  add_foreign_key "hosts", "organizations"
  add_foreign_key "issue_disposition_changes", "issues"
  add_foreign_key "issues", "organizations"
  add_foreign_key "normalized_denials", "raw_events"
  add_foreign_key "occurrences", "host_snapshots"
  add_foreign_key "occurrences", "hosts"
  add_foreign_key "occurrences", "issues"
  add_foreign_key "occurrences", "normalized_denials"
  add_foreign_key "occurrences", "organizations"
  add_foreign_key "occurrences", "raw_events"
  add_foreign_key "policy_draft_entries", "policy_drafts"
  add_foreign_key "policy_drafts", "organizations"
  add_foreign_key "raw_audit_records", "raw_events"
  add_foreign_key "raw_events", "agent_installations"
  add_foreign_key "raw_events", "host_snapshots"
  add_foreign_key "raw_events", "hosts"
  add_foreign_key "raw_events", "organizations"
  add_foreign_key "resolution_intent_changes", "issues"
  add_foreign_key "resolution_intents", "issues"
end
