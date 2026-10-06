class IngestEvents
  COMPLETION_REASONS = %w[eoe timeout capacity shutdown].freeze
  TYPE_CODES = { "avc" => 1400, "user_avc" => 1107, "syscall" => 1300, "path" => 1302, "avc_path" => 1402, "proctitle" => 1327, "execve" => 1309, "cwd" => 1307, "eoe" => 1320, "mac_policy_load" => 1403, "mac_config_change" => 1405, "mac_status" => 1404, "user_mac_config_change" => 2312 }.freeze

  def self.type_code(value)
    return value if value.is_a?(Integer)
    return unless value.is_a?(String)

    TYPE_CODES.fetch(value.downcase) { value[/\Aunknown\[(\d+)\]\z/i, 1]&.to_i }
  end

  class InvalidRequest < StandardError
    attr_reader :details

    def initialize(details)
      @details = details
      super("request validation failed")
    end
  end

  class EvidenceConflict < InvalidRequest; end

  def initialize(organization:, payload:)
    @organization = organization
    @payload = payload
  end

  def call
    validate_request!
    @server_received_at = Time.current
    raw_events = []
    ActiveRecord::Base.transaction do
      host = Host.find_for_ingestion!(@organization, @payload["host_id"])
      host.with_lock do
        now = Time.current
        host.last_seen_at = now
        host.save!
        @agent_installation = host.agent_installations.find_or_create_by!(organization: @organization) do |installation|
          installation.name = host.external_id
        end
        @agent_installation.update!(last_seen_at: now, agent_version: @payload.dig("agent", "version"))
        observed_at = Time.iso8601(@payload["host_observed_at"]) if present?(@payload["host_observed_at"])
        @payload.fetch("events").each do |event|
          timestamp = Time.iso8601(event.dig("audit_event", "timestamp"))
          sequence = Integer(event.dig("audit_event", "sequence"))
          snapshot = host_snapshot(host, observed_at, event, timestamp, sequence, @payload.fetch("boot_id")) if observed_at
          snapshot, raw_event = persist_event!(@organization, host, snapshot, event)
          raw_events << raw_event if raw_event
        end
      end
    end
    raw_events
  rescue ActiveRecord::RecordNotUnique
    reconcile_duplicate!
  end

  private

  def validate_request!
    unless @payload.is_a?(Hash)
      raise InvalidRequest, [detail("request", "object_required")]
    end

    details = []
    details << detail("schema_version", "unsupported_schema_version") unless @payload["schema_version"] == 4
    details << detail("agent.version", "required") if blank?(@payload.dig("agent", "version"))
    details << detail("host_id", "required") if blank?(@payload["host_id"])
    details << detail("boot_id", "required") if blank?(@payload["boot_id"])
    details << detail("host_observed_at", "invalid_timestamp") if present?(@payload["host_observed_at"]) && !timestamp?(@payload["host_observed_at"])
    fields = @payload.fetch("checkpoint_invalidated_fields", [])
    unless fields.is_a?(Array) && (fields - RawEvent::CHECKPOINT_FIELDS).empty? && fields.uniq == fields
      details << detail("checkpoint_invalidated_fields", "invalid_checkpoint_fields")
    end
    details << detail("events", "required") unless @payload["events"].is_a?(Array) && @payload["events"].any?
    Array(@payload["events"]).each_with_index do |event, index|
      details.concat(validate_event(event, index))
    end
    raise InvalidRequest, details if details.any?
  end

  def validate_event(event, index)
    path = "events[#{index}]"
    details = []
    unless event.is_a?(Hash)
      return [detail(path, "object_required")]
    end

    audit_event = event["audit_event"]
    details << detail("#{path}.category", "unknown_category") unless %w[avc selinux_administrative].include?(event["category"])
    details << detail("#{path}.audit_event", "object_required") unless audit_event.is_a?(Hash)
    details << detail("#{path}.audit_event.timestamp", "required") if !audit_event.is_a?(Hash) || blank?(audit_event["timestamp"])
    details << detail("#{path}.audit_event.timestamp", "invalid_timestamp") if audit_event.is_a?(Hash) && present?(audit_event["timestamp"]) && !timestamp?(audit_event["timestamp"])
    details << detail("#{path}.audit_event.sequence", "required") if !audit_event.is_a?(Hash) || audit_event["sequence"].nil?
    details << detail("#{path}.audit_event.sequence", "invalid_integer") if audit_event.is_a?(Hash) && !integer?(audit_event["sequence"])
    details << detail("#{path}.agent_received_at", "required") if blank?(event["agent_received_at"])
    details << detail("#{path}.agent_received_at", "invalid_timestamp") if present?(event["agent_received_at"]) && !timestamp?(event["agent_received_at"])
    details << detail("#{path}.completion_reason", "unknown_completion_reason") unless event.is_a?(Hash) && COMPLETION_REASONS.include?(event["completion_reason"])
    records = event.is_a?(Hash) ? event["records"] : nil
    details << detail("#{path}.records", "required") unless records.is_a?(Array) && records.any?
    Array(records).each_with_index do |record, position|
      record_path = "#{path}.records[#{position}]"
      unless record.is_a?(Hash)
        details << detail(record_path, "object_required")
        next
      end
      details << detail("#{record_path}.position", "position_mismatch") unless record["position"] == position
      details << detail("#{record_path}.type", "required") if record["type"].nil?
      details << detail("#{record_path}.type", "invalid_type") if !record["type"].nil? && !valid_type?(record["type"])
      details << detail("#{record_path}.timestamp", "required") if blank?(record["timestamp"])
      details << detail("#{record_path}.timestamp", "invalid_timestamp") if present?(record["timestamp"]) && !timestamp?(record["timestamp"])
      details << detail("#{record_path}.timestamp", "event_identity_mismatch") if present?(record["timestamp"]) && audit_event.is_a?(Hash) && record["timestamp"] != audit_event["timestamp"]
      details << detail("#{record_path}.sequence", "required") if record["sequence"].nil?
      details << detail("#{record_path}.sequence", "invalid_integer") if !record["sequence"].nil? && !integer?(record["sequence"])
      details << detail("#{record_path}.sequence", "event_identity_mismatch") if !record["sequence"].nil? && audit_event.is_a?(Hash) && record["sequence"] != audit_event["sequence"]
      details << detail("#{record_path}.payload", "required") if blank?(record["payload"])
      begin
        Base64.strict_decode64(record.fetch("payload"))
      rescue ArgumentError, KeyError
        details << detail("#{record_path}.payload", "invalid_base64")
      end
      details << detail("#{record_path}.type_name", "required") if blank?(record["type_name"])
    end
    record_types = Array(records).filter_map { |record| type_code(record["type"]) if record.is_a?(Hash) }
    if event["category"] == "avc" && (record_types & [ 1400, 1107 ]).empty?
      details << detail("#{path}.category", "avc_record_required")
    elsif event["category"] == "selinux_administrative" && (record_types & [1403, 1404]).empty? && boolean_changes(event).empty? && !port_record?(event)
      details << detail("#{path}.category", "supported_administrative_record_required")
    end
    details
  end

  def persist_event!(organization, host, snapshot, event)
    timestamp = Time.iso8601(event.dig("audit_event", "timestamp"))
    sequence = Integer(event.dig("audit_event", "sequence"))
    boot_id = @payload.fetch("boot_id")
    digest = EvidenceDigest.call(event)
    host_observed_at = Time.iso8601(@payload["host_observed_at"]) if present?(@payload["host_observed_at"])
    existing = organization.raw_events.find_by({ host: host, boot_id: boot_id, audit_timestamp: timestamp, audit_sequence: sequence })
    if existing
      if existing.evidence_digest == digest
        # Replayed envelope metadata can strengthen trust uncertainty, never
        # replace the original source reference or erase an existing mask.
        fields = existing.checkpoint_invalidated_fields | checkpoint_invalidated_fields(host, event, timestamp, sequence, existing.host_observed_at)
        existing.update!(checkpoint_invalidated_fields: fields.sort) unless fields.sort == existing.checkpoint_invalidated_fields.sort
        return [snapshot, existing]
      end

      raise EvidenceConflict, [detail("events", "conflicting_duplicate")]
    end

    raw_event = organization.raw_events.create!({
      agent_installation: @agent_installation,
      host: host,
      host_snapshot: snapshot,
      category: event.fetch("category"),
      transition_type: transition_type(event),
      boolean_changes: boolean_changes(event),
      enforcement_changes: enforcement_changes(event),
      port_changes: port_changes(event),
      checkpoint_invalidated_fields: checkpoint_invalidated_fields(host, event, timestamp, sequence, host_observed_at),
      audit_timestamp: timestamp,
      audit_sequence: sequence,
      boot_id: boot_id,
      completion_reason: event.fetch("completion_reason"),
      evidence_digest: digest,
      agent_received_at: Time.iso8601(event.fetch("agent_received_at")),
      host_observed_at: host_observed_at,
      server_received_at: @server_received_at,
      schema_version: @payload.fetch("schema_version"),
      file_context_observations: [],
      policy_evaluations: []
    })
    event.fetch("records").each do |record|
      raw_event.raw_audit_records.create!({
        position: record.fetch("position"),
      record_type: type_code(record.fetch("type")),
        type_name: record.fetch("type_name"),
        audit_timestamp: Time.iso8601(record.fetch("timestamp")),
        sequence: Integer(record.fetch("sequence")),
        payload: Base64.strict_decode64(record.fetch("payload"))
      })
    end
    invalidate_pre_transition_associations(raw_event) if raw_event.transition_type
    [snapshot, raw_event]
  end

  def host_snapshot(host, observed_at, event, audit_timestamp, audit_sequence, boot_id)
    if event["category"] == "avc"
      return if observed_at >= audit_timestamp

      transition = host.raw_events.policy_transitions.where(boot_id: boot_id)
        .where("(audit_timestamp, audit_sequence) <= (?, ?)", audit_timestamp, audit_sequence)
        .order(audit_timestamp: :desc, audit_sequence: :desc)
        .first
      return if transition && observed_at <= transition.audit_timestamp
    end

    observation = host.host_snapshot_observations.joins(:host_snapshot)
      .where("first_observed_at <= ? AND last_observed_at >= ?", observed_at, observed_at)
      .where("host_snapshots.details ->> 'boot_id' = ?", boot_id)
      .order(last_received_at: :desc, id: :desc)
      .first
    observation&.host_snapshot
  end

  def transition_type(event)
    return unless event["category"] == "selinux_administrative"

    successful_load = event.fetch("records").any? do |record|
      type_code(record["type"]) == 1403 && Base64.strict_decode64(record.fetch("payload")).split.include?("res=1")
    end
    return "policy_load" if successful_load

    return "boolean_change" if boolean_changes(event).any? { |change| change["success"] && change["old_value"] != change["new_value"] }

    return "enforcement_change" if enforcement_changes(event).any? { |change| change["success"] && change["old_mode"] != change["new_mode"] }

    "port_change" if port_changes(event).any? { |change| change["success"] }
  end

  def boolean_changes(event)
    Array(event["records"]).filter_map do |record|
      next unless record.is_a?(Hash) && type_code(record["type"]) == 1405

      RawEvent.boolean_change(Base64.strict_decode64(record.fetch("payload")))
    rescue ArgumentError, KeyError
      nil
    end
  end

  def enforcement_changes(event)
    Array(event["records"]).filter_map do |record|
      next unless record.is_a?(Hash) && type_code(record["type"]) == 1404

      RawEvent.enforcement_change(Base64.strict_decode64(record.fetch("payload")))
    rescue ArgumentError, KeyError
      nil
    end
  end

  def checkpoint_invalidated_fields(host, event, time, sequence, observed_at)
    fields = @payload.fetch("checkpoint_invalidated_fields", []).dup
    if event["category"] == "avc" && observed_at
      transitions = host.raw_events.state_transitions.where(boot_id: @payload["boot_id"])
        .where("(audit_timestamp, audit_sequence) <= (?, ?)", time, sequence).where("audit_timestamp >= ?", observed_at).distinct.pluck(:transition_type)
      fields |= CheckpointTrust.fields_for(transitions)
    end
    fields.sort
  end

  def port_record?(event)
    Array(event["records"]).any? do |record|
      record.is_a?(Hash) && type_code(record["type"]) == 2312 && RawEvent.port_record?(Base64.strict_decode64(record.fetch("payload")))
    rescue ArgumentError, KeyError
      false
    end
  end

  def port_changes(event)
    Array(event["records"]).filter_map do |record|
      next unless record.is_a?(Hash) && type_code(record["type"]) == 2312

      RawEvent.port_change(Base64.strict_decode64(record.fetch("payload")))
    rescue ArgumentError, KeyError
      nil
    end
  end

  # Transport order is not audit order. Retract unsafe associations, never
  # assign a later checkpoint to an earlier AVC. Called under the host lock.
  def invalidate_pre_transition_associations(transition)
    events = transition.host.raw_events.where(boot_id: transition.boot_id, category: "avc")
      .where("(audit_timestamp, audit_sequence) >= (?, ?)", transition.audit_timestamp, transition.audit_sequence)
      .where("host_observed_at <= ?", transition.audit_timestamp)
    fields = CheckpointTrust.fields_for(transition.transition_type)
    quoted = ActiveRecord::Base.connection.quote(fields.to_json)
    events.update_all("checkpoint_invalidated_fields = (SELECT jsonb_agg(DISTINCT value ORDER BY value) FROM jsonb_array_elements(checkpoint_invalidated_fields || #{quoted}::jsonb))")
    if CheckpointTrust::WITHHELD_ASSOCIATIONS.include?(transition.transition_type)
      transition.host.occurrences.where(raw_event_id: events.select(:id)).update_all(host_snapshot_id: nil)
      events.update_all(host_snapshot_id: nil)
    end
  end

  def reconcile_duplicate!
    host = @organization.hosts.find_by({ external_id: @payload["host_id"] })
    raise unless host

    @payload.fetch("events").each do |event|
      identity = {
        host: host,
        boot_id: @payload.fetch("boot_id"),
        audit_timestamp: Time.iso8601(event.dig("audit_event", "timestamp")),
        audit_sequence: event.dig("audit_event", "sequence")
      }
      existing = @organization.raw_events.find_by(identity)
      raise unless existing
      raise EvidenceConflict, [detail("events", "conflicting_duplicate")] unless existing.evidence_digest == EvidenceDigest.call(event)
    end
    nil
  end

  def detail(path, code)
    { "path" => path, "code" => code }
  end

  def blank?(value)
    value.nil? || value == ""
  end

  def present?(value)
    !blank?(value)
  end

  def timestamp?(value)
    Time.iso8601(value.to_s)
    true
  rescue ArgumentError
    false
  end

  def integer?(value)
    value.is_a?(Integer)
  end

  def valid_type?(value)
    !self.class.type_code(value).nil?
  end

  def type_code(value)
    self.class.type_code(value)
  end
end
