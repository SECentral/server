class PersistExpectedContextObservation
  FILE_TYPES = %w[file dir pipe chr_file blk_file lnk_file sock_file].freeze
  STATUSES = %w[resolved unavailable error].freeze
  OBJECT_CLASS_TYPES = {
    "file" => "file", "dir" => "dir", "fifo_file" => "pipe", "chr_file" => "chr_file",
    "blk_file" => "blk_file", "lnk_file" => "lnk_file", "sock_file" => "sock_file"
  }.freeze

  class InvalidRequest < StandardError
    attr_reader :details

    def initialize(details)
      @details = details
      super("expected-context observation request is invalid")
    end
  end

  class EvidenceConflict < StandardError; end

  def self.call(organization:, payload:)
    new(organization, payload).call
  end

  def initialize(organization, payload)
    @organization = organization
    @payload = payload
  end

  def call
    validate!
    host = @organization.hosts.find_by!(external_id: @payload.fetch("host_id"))
    audit_event = @payload.fetch("audit_event")
    raw_event = @organization.raw_events.find_by!(
      host: host,
      boot_id: @payload.fetch("boot_id"),
      audit_timestamp: database_precision(Time.iso8601(audit_event.fetch("timestamp"))),
      audit_sequence: Integer(audit_event.fetch("sequence"))
    )
    host_observed_at = Time.iso8601(@payload["host_observed_at"]) if present?(@payload["host_observed_at"])
    unless raw_event.avc? && same_database_timestamp?(raw_event.host_observed_at, host_observed_at)
      raise InvalidRequest, [ detail("host_observed_at", "event_checkpoint_mismatch") ]
    end
    persist!(raw_event)
  end

  private

  def validate!
    details = []
    unless @payload.is_a?(Hash)
      raise InvalidRequest, [ detail("request", "object_required") ]
    end
    details << detail("schema_version", "unsupported_version") unless @payload["schema_version"] == 1
    agent = @payload["agent"]
    details << detail("agent", "object_required") unless agent.is_a?(Hash)
    details << detail("agent.version", "invalid_value") if agent.is_a?(Hash) && !nonempty_string?(agent["version"])
    details << detail("host_id", "invalid_value") unless nonempty_string?(@payload["host_id"])
    details << detail("boot_id", "invalid_value") unless nonempty_string?(@payload["boot_id"])
    audit_event = @payload["audit_event"]
    details << detail("audit_event", "object_required") unless audit_event.is_a?(Hash)
    if audit_event.is_a?(Hash)
      details << detail("audit_event.timestamp", "invalid_timestamp") unless audit_event["timestamp"].is_a?(String) && timestamp?(audit_event["timestamp"])
      details << detail("audit_event.sequence", "invalid_integer") unless audit_event["sequence"].is_a?(Integer) && audit_event["sequence"].between?(0, 4_294_967_295)
    end
    details << detail("host_observed_at", "invalid_timestamp") if present?(@payload["host_observed_at"]) && (!@payload["host_observed_at"].is_a?(String) || !timestamp?(@payload["host_observed_at"]))
    observation = @payload["observation"]
    details << detail("observation", "object_required") unless observation.is_a?(Hash)
    if observation.is_a?(Hash)
      path = observation["path"]
      details << detail("observation.path", "absolute_path_required") unless path.is_a?(String) && path.start_with?("/") && path.bytesize <= 4096 && !path.include?("\0")
      object_class = observation["object_class"]
      details << detail("observation.object_class", "invalid_value") unless object_class.is_a?(String) && object_class.match?(/\A[a-z0-9_]{1,64}\z/)
      details << detail("observation.observed_at", "invalid_timestamp") unless observation["observed_at"].is_a?(String) && timestamp?(observation["observed_at"])
      details << detail("observation.resolver", "unsupported_resolver") unless observation["resolver"] == "matchpathcon"
      status = observation["status"]
      details << detail("observation.status", "unknown_status") unless STATUSES.include?(status)
      file_type = observation["file_type"]
      details << detail("observation.file_type", "unsupported_type") if present?(file_type) && !FILE_TYPES.include?(file_type)
      if status == "resolved"
        expected_class_type = OBJECT_CLASS_TYPES[object_class]
        details << detail("observation.file_type", "does_not_match_object_class") unless expected_class_type && file_type == expected_class_type
        context = observation["expected_context"]
        parts = context.to_s.split(":", 4)
        details << detail("observation.expected_context", "invalid_context") unless context.is_a?(String) && context.bytesize <= 512 && parts.length >= 3 && parts.take(3).all?(&:present?)
        details << detail("observation.reason", "not_allowed_for_resolved") if present?(observation["reason"])
      elsif STATUSES.include?(status)
        details << detail("observation.reason", "required") if blank?(observation["reason"])
        details << detail("observation.reason", "too_long") if observation["reason"].is_a?(String) && observation["reason"].bytesize > 256
        details << detail("observation.expected_context", "not_allowed") if present?(observation["expected_context"])
      end
    end
    raise InvalidRequest, details if details.any?
  end

  def persist!(raw_event)
    observation = @payload.fetch("observation").slice(
      "path", "object_class", "file_type", "expected_context", "observed_at", "resolver", "status", "reason"
    ).compact
    observation["kind"] = "expected_context"
    observation["host_observed_at"] = @payload["host_observed_at"] if present?(@payload["host_observed_at"])
    unless raw_event.avc? && raw_event.normalized_denials.any? { |denial| observation_matches_denial?(observation, denial) }
      raise InvalidRequest, [ detail("observation.path", "not_in_retained_avc_evidence") ]
    end

    raw_event.with_lock do
      values = Array(raw_event.file_context_observations)
      existing = values.find do |value|
        value["kind"] == "expected_context" &&
          value["path"] == observation["path"] &&
          value["object_class"] == observation["object_class"] &&
          value["file_type"] == observation["file_type"]
      end
      if existing
        raise EvidenceConflict, "expected-context result conflicts with an existing observation" unless existing == observation
      else
        raw_event.update!(file_context_observations: values + [ observation ])
      end
    end
    raw_event
  end

  def observation_matches_denial?(observation, denial)
    denial.target_class == observation["object_class"] &&
      Array(denial.details.to_h.dig("target_evidence", "filesystem_paths")).include?(observation["path"])
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

  def nonempty_string?(value)
    value.is_a?(String) && value.present? && value.bytesize <= 4096
  end

  def timestamp?(value)
    return false unless value.is_a?(String) && value.bytesize <= 64

    Time.iso8601(value.to_s)
    true
  rescue ArgumentError
    false
  end

  def same_database_timestamp?(left, right)
    return left.nil? && right.nil? if left.nil? || right.nil?

    left.to_time.to_i == right.to_time.to_i && left.to_time.usec == right.to_time.usec
  end

  def database_precision(value)
    Time.at(value.to_time.to_i, value.to_time.usec).utc
  end
end
