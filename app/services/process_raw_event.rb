class ProcessRawEvent
  NORMALIZATION_VERSION = 1

  def self.call(raw_event)
    new(raw_event).call
  end

  def initialize(raw_event)
    @raw_event = raw_event
  end

  def call
    return unless @raw_event.avc?

    @raw_event.host.with_lock do
      @raw_event.reload
      results = AvcNormalizer.call(@raw_event.raw_audit_records.to_a)
      results.each_with_index do |result, ordinal|
        denial = PersistNormalizedDenial.call(@raw_event, result, ordinal: ordinal, normalization_version: NORMALIZATION_VERSION)
        persist_occurrence(denial, result)
      end
    end
  end

  private

  def persist_occurrence(denial, result)
    occurrence = denial.occurrence || Occurrence.new
    occurrence.organization = @raw_event.organization
    occurrence.host = @raw_event.host
    occurrence.host_snapshot = @raw_event.host_snapshot
    occurrence.raw_event = @raw_event
    occurrence.normalized_denial = denial
    occurrence.occurred_at = @raw_event.audit_timestamp
    if result[:status] == "ok"
      issue = find_or_create_issue(result)
      issue.with_lock do
        fingerprint = FingerprintV3.call(result)
        previous = occurrence.issue_signature if occurrence.issue_id == issue.id
        signature = if previous && (previous.fingerprint_version != 3 || previous.fingerprint_digest == fingerprint.fetch(:digest))
          previous
        else
          issue.signatures.find_or_initialize_by(fingerprint_version: fingerprint.fetch(:version), fingerprint_digest: fingerprint.fetch(:digest))
        end
        signature.permissions = result.fetch(:permissions).uniq.sort if signature.fingerprint_version == 3
        signature.first_seen_at = [signature.first_seen_at, occurrence.occurred_at].compact.min
        signature.last_seen_at = [signature.last_seen_at, occurrence.occurred_at].compact.max
        if occurrence.new_record? && signature.status == "resolved"
          signature.status = "open"
          signature.reopened_at = Time.current
          signature.regressions_count += 1
        end
        signature.save!
        occurrence.issue = issue
        occurrence.issue_signature = signature
        occurrence.save!
        issue.refresh_from_signatures!
      end
    else
      occurrence.issue = nil
      occurrence.issue_signature = nil
      occurrence.save!
    end
    occurrence
  end

  def find_or_create_issue(denial)
    identity = {
      source_type: denial.fetch(:source_type),
      target_type: denial.fetch(:target_type),
      target_class: denial.fetch(:target_class)
    }
    @raw_event.organization.issues.create_or_find_by!(identity) do |issue|
      fingerprint = FingerprintV4.call(denial)
      issue.assign_attributes(fingerprint_version: fingerprint.fetch(:version), fingerprint_digest: fingerprint.fetch(:digest),
        permissions: denial.fetch(:permissions).uniq.sort, first_seen_at: @raw_event.audit_timestamp, last_seen_at: @raw_event.audit_timestamp)
    end
  end
end
