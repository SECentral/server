class ProcessRawEvent
  NORMALIZATION_VERSION = 2

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
      old_occurrences = @raw_event.occurrences.includes(:normalized_denial).to_a
      replay = old_occurrences.any?
      results = AvcNormalizer.call(@raw_event.raw_audit_records.to_a)
      current = []
      results.each_with_index do |result, ordinal|
        denial = PersistNormalizedDenial.call(@raw_event, result, ordinal: ordinal, normalization_version: NORMALIZATION_VERSION)
        # Reuse a single unchanged interpretation so its URLs and reviews survive.
        previous = old_occurrences.find do |item|
          original = item.normalized_denial
          results.one? && original.attributes.symbolize_keys.slice(:source_context, :target_context, :target_class, :permissions) ==
            result.slice(:source_context, :target_context, :target_class, :permissions)
        end
        current << persist_occurrence(denial, result, previous: previous, replay: replay)
      end
      current_ids = current.map(&:id)
      superseded = old_occurrences.reject { |item| current_ids.include?(item.id) }
      superseded.each { |item| item.update!(superseded_at: Time.current) }
      issues = Issue.where(id: superseded.filter_map(&:issue_id).uniq).order(:id)
      issues.each do |issue|
        issue.with_lock do
          issue.update_columns(occurrences_count: issue.occurrences.count)
          issue.refresh_from_signatures!
        end
      end
    end
  end

  private

  def persist_occurrence(denial, result, previous:, replay:)
    occurrence = denial.occurrence || previous || Occurrence.new
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
        if occurrence.new_record? && !replay && signature.status == "resolved"
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
