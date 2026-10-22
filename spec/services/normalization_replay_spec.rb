require "rails_helper"
require_relative "../support/port_resolution_fixtures"

RSpec.describe "Normalization replay" do
  include PortResolutionFixtures

  around do |example|
    ActiveRecord::Base.transaction do
      example.run
      raise ActiveRecord::Rollback
    end
  end

  it "supersedes a mixed interpretation without losing raw evidence, URLs or reviewed signature history" do
    issue, original, = port_fixture
    raw = original.raw_event
    issue.update!(source_type: "mysqld_t", target_type: "var_t", target_class: "file", permissions: %w[add_name create read write])
    old = original.normalized_denial
    old.update!(source_type: "mysqld_t", target_type: "var_t", target_class: "file", permissions: issue.permissions)
    signature = issue.signatures.create!(fingerprint_version: 3, fingerprint_digest: "legacy-mixed", permissions: issue.permissions,
      first_seen_at: raw.audit_timestamp, last_seen_at: raw.audit_timestamp)
    original.update!(issue_signature: signature)
    signature.transition_to!("ignored")
    signature.set_disposition!("expected_harmless", note: "Original reviewed interpretation")
    intent = ResolutionIntent.create!(issue: issue, candidate_id: "legacy-review", candidate_kind: "enable_boolean",
      selected_intent: "Original intent", operator: "tester", selected_at: Time.current, status: "selected",
      evidence_version: "old", evidence_basis: { occurrence_id: original.id }, semantic_plan_basis: { scope: "original" },
      plan_semantics_version: 1, plan_snapshot: { occurrence_id: original.id, scope: "original" })
    payloads = [
      'type=AVC denied { write add_name } name="db" scontext=u:r:mysqld_t:s0 tcontext=u:object_r:var_t:s0 tclass=dir permissive=1',
      'type=AVC denied { create read write } path="/srv/db/file" scontext=u:r:mysqld_t:s0 tcontext=system_u:object_r:var_t:s0 tclass=file permissive=1',
      'type=SYSCALL pid=123 exe="/usr/libexec/mariadbd" subj=u:r:mysqld_t:s0 syscall=257 success=yes exit=3'
    ]
    payloads.each_with_index do |payload, position|
      raw.raw_audit_records.create!(position: position, record_type: position == 2 ? 1300 : 1400,
        type_name: position == 2 ? "SYSCALL" : "AVC", audit_timestamp: raw.audit_timestamp, sequence: raw.audit_sequence, payload: payload)
    end

    2.times { ProcessRawEvent.call(raw) }

    current = raw.occurrences.includes(:normalized_denial).to_a
    expect(current.size).to eq(2)
    expect(current.map { |o| o.normalized_denial.target_class }).to contain_exactly("dir", "file")
    expect(current).to all(satisfy { |o| o.normalized_denial.normalization_version == 2 })
    expect(Occurrence.where(id: original.id)).to be_empty
    expect(Occurrence.unscoped.find(original.id).superseded_at).to be_present
    expect(old.reload.permissions).to eq(%w[add_name create read write])
    expect(raw.raw_audit_records.order(:position).pluck(:payload)).to eq(payloads)
    expect(signature.reload).to have_attributes(status: "ignored", disposition: "expected_harmless")
    expect(issue.disposition_changes.sole.note).to eq("Original reviewed interpretation")
    expect(current.map(&:issue_signature_id)).not_to include(signature.id)
    expect(current.map(&:issue).map(&:status)).to all(eq("open"))
    expect(issue.reload.permissions).to eq(%w[create read write])
    expect(intent.reload.plan_snapshot).to eq("occurrence_id" => original.id, "scope" => "original")
    expect(ResolutionWorkflow.new(issue, operator: "tester").call).to include(freshness: "no_longer_supported", change_plan: nil)
    expect(raw.normalized_denials.count).to eq(3)
    expect(current.map(&:issue).uniq).to all(satisfy { |i| i.reload.occurrences_count == i.occurrences.count })
    PolicyFactRequest.for_event(raw)
    identity = raw.checkpoint_policy_identity
    expect(PolicyFact.where(policy_identity: identity, object_class: "file", permission: "add_name")).to be_empty
    expect(PolicyFact.where(policy_identity: identity, object_class: "dir", permission: "add_name")).to exist
  end
end
