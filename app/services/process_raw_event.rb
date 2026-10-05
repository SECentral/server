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
      fingerprint = FingerprintV3.call(result)
      occurrence.issue = find_or_create_issue(fingerprint, result)
    else
      occurrence.issue = nil
    end
    occurrence.save!
    occurrence
  end

  def find_or_create_issue(fingerprint, denial)
    attrs = {
      fingerprint_version: fingerprint.fetch(:version),
      fingerprint_digest: fingerprint.fetch(:digest),
      source_type: denial.fetch(:source_type),
      target_type: denial.fetch(:target_type),
      target_class: denial.fetch(:target_class),
      permissions: denial.fetch(:permissions).uniq.sort,
      first_seen_at: @raw_event.audit_timestamp,
      last_seen_at: @raw_event.audit_timestamp
    }
    issue = @raw_event.organization.issues.find_or_initialize_by({ fingerprint_version: attrs[:fingerprint_version], fingerprint_digest: attrs[:fingerprint_digest] })
    attrs[:permissions] = (Array(issue.permissions) + Array(denial[:permissions])).uniq.sort
    if issue.persisted? && issue.status == "resolved"
      issue.status = "open"
      issue.reopened_at = Time.current
      issue.regressions_count += 1
    end
    first_seen_at = issue.first_seen_at
    last_seen_at = issue.last_seen_at
    issue.assign_attributes(attrs)
    issue.first_seen_at = [first_seen_at, @raw_event.audit_timestamp].compact.min
    issue.last_seen_at = [last_seen_at, @raw_event.audit_timestamp].compact.max
    issue.save!
    issue
  rescue ActiveRecord::RecordNotUnique
    retry
  end
end
