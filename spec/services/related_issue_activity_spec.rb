require "rails_helper"
require_relative "../support/port_resolution_fixtures"

RSpec.describe RelatedIssueActivity do
  include PortResolutionFixtures

  around do |example|
    ActiveRecord::Base.transaction do
      example.run
      raise ActiveRecord::Rollback
    end
  end

  it "links distinct decisions in the same audit event without inheriting lifecycle" do
    issue, first, = port_fixture
    other = issue.dup
    other.assign_attributes(target_class: "file", fingerprint_digest: "other", status: "ignored")
    other.save!
    denial = first.normalized_denial.dup
    denial.assign_attributes(ordinal: 1, target_class: "file")
    denial.save!
    occurrence = first.dup
    occurrence.assign_attributes(issue: other, normalized_denial: denial)
    occurrence.save!

    expect(described_class.call(issue)).to include(include(issue_id: other.id, basis: "same_audit_event", source_occurrence_id: first.id, occurrence_id: occurrence.id))
    expect(issue.reload.status).to eq("open")
    expect(other.reload.status).to eq("ignored")
  end

  it "requires same host, boot and complete process identity within a bounded time window" do
    issue, first, = port_fixture
    raw = first.raw_event
    raw.raw_audit_records.create!(position: 0, record_type: 1300, type_name: "SYSCALL", audit_timestamp: raw.audit_timestamp,
      sequence: raw.audit_sequence, payload: 'type=SYSCALL pid=123 exe="/usr/libexec/mariadbd" subj=u:r:mysqld_t:s0')
    other = issue.dup
    other.assign_attributes(target_class: "file", fingerprint_digest: "other")
    other.save!
    event = raw.dup
    event.assign_attributes(audit_sequence: 2, audit_timestamp: raw.audit_timestamp + 0.1.seconds)
    event.save!
    event.raw_audit_records.create!(position: 0, record_type: 1300, type_name: "SYSCALL", audit_timestamp: event.audit_timestamp,
      sequence: 2, payload: raw.raw_audit_records.sole.payload)
    denial = first.normalized_denial.dup
    denial.raw_event = event
    denial.save!
    neighbor = first.dup
    neighbor.assign_attributes(issue: other, raw_event: event, normalized_denial: denial, occurred_at: event.audit_timestamp)
    neighbor.save!
    expect(described_class.call(issue)).to include(include(issue_id: other.id, basis: "same_process_window"))
    event.update!(boot_id: "different")
    expect(described_class.call(issue)).to be_empty
    event.update!(boot_id: raw.boot_id)
    event.raw_audit_records.sole.update!(payload: 'type=SYSCALL pid=124 exe="/usr/libexec/mariadbd" subj=u:r:mysqld_t:s0')
    expect(described_class.call(issue)).to be_empty
    event.raw_audit_records.sole.update!(payload: raw.raw_audit_records.sole.payload)
    foreign = Organization.create!(name: "unrelated-activity")
    other.update!(organization: foreign)
    expect(described_class.call(issue)).to be_empty
    other.update!(organization: issue.organization)
    event.raw_audit_records.sole.update!(payload: 'type=SYSCALL pid=123 subj=u:r:mysqld_t:s0')
    expect(described_class.call(issue)).to be_empty
    event.raw_audit_records.sole.update!(payload: raw.raw_audit_records.sole.payload)
    neighbor.update!(occurred_at: first.occurred_at + 3.seconds)
    expect(described_class.call(issue)).to be_empty
  end
end
