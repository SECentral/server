class RawEvent < ApplicationRecord
  belongs_to :organization
  belongs_to :agent_installation
  belongs_to :host
  belongs_to :host_snapshot, optional: true
  has_many :raw_audit_records, -> { order(:position) }, dependent: :restrict_with_exception
  has_many :normalized_denials, dependent: :restrict_with_exception
  has_many :occurrences, dependent: :restrict_with_exception

  validates :audit_timestamp, :audit_sequence, :boot_id, :completion_reason,
    :evidence_digest, :agent_received_at, :server_received_at, presence: true
  validates :category, inclusion: { in: %w[avc selinux_administrative] }
  POLICY_TRANSITIONS = CheckpointTrust::WITHHELD_ASSOCIATIONS
  STATE_TRANSITIONS = CheckpointTrust::TRANSITION_FIELDS.keys.freeze
  CHECKPOINT_FIELDS = CheckpointTrust::FIELDS
  scope :state_transitions, -> { where(transition_type: STATE_TRANSITIONS) }
  scope :policy_transitions, -> { where(transition_type: POLICY_TRANSITIONS) }
  validates :transition_type, inclusion: { in: STATE_TRANSITIONS }, allow_nil: true

  def self.boolean_change(payload)
    fields = {}
    payload.split.each do |field|
      key, value = field.split("=", 2)
      next unless %w[bool val old_val res].include?(key)
      return if fields.key?(key)

      fields[key] = value
    end
    return unless fields["bool"].to_s.match?(/\A[A-Za-z_][A-Za-z0-9_]*\z/) &&
      %w[0 1].include?(fields["val"]) && %w[0 1].include?(fields["old_val"])

    { "name" => fields["bool"], "old_value" => fields["old_val"].to_i,
      "new_value" => fields["val"].to_i, "success" => !fields.key?("res") || fields["res"] == "1",
      "success_source" => fields.key?("res") ? "res" : "kernel_boolean_commit" }
  end

  def avc?
    category == "avc"
  end

  def self.enforcement_change(payload)
    fields = {}
    payload.split.each do |field|
      key, value = field.split("=", 2)
      next unless %w[enforcing old_enforcing enabled old-enabled lsm res old_enabled success operation].include?(key)
      return if fields.key?(key)

      fields[key] = value
    end
    return unless %w[0 1].include?(fields["enforcing"]) && %w[0 1].include?(fields["old_enforcing"]) &&
      fields["enabled"] == "1" && fields["old-enabled"] == "1" && fields["lsm"] == "selinux" &&
      (fields.keys & %w[old_enabled success operation]).empty?

    { "old_mode" => fields["old_enforcing"] == "1" ? "enforcing" : "permissive",
      "new_mode" => fields["enforcing"] == "1" ? "enforcing" : "permissive", "success" => fields["res"] == "1" }
  end

  def checkpoint_enforcement_mode(snapshot = host_snapshot)
    checkpoint_trust(snapshot).enforcement || "unknown"
  end

  def checkpoint_policy_identity(snapshot = host_snapshot)
    checkpoint_trust(snapshot).policy_identity
  end

  def checkpoint_port_inventory(snapshot = host_snapshot)
    checkpoint_trust(snapshot).ports
  end

  def checkpoint_trust(snapshot = host_snapshot)
    CheckpointTrust.new(snapshot, checkpoint_invalidated_fields)
  end

  def self.file_context_record?(payload)
    payload.scan(/(?:\A|\s)msg='([^']*)'(?:\s|\z)/).any? { |body| body.first == "resrc=fcontext" || body.first.start_with?("resrc=fcontext ") }
  end

  def self.file_context_change(payload)
    fields = user_change_fields(payload)
    return unless fields && fields["resrc"] == "fcontext" && %w[add modify delete].include?(fields["op"]) && %w[any file].include?(fields["ftype"]) &&
      (fields.keys & %w[success old_tcontext old_type sglob lport proto]).empty?
    expression = fields["tglob"]
    return unless expression&.start_with?('"/') && expression.end_with?('"') && expression.bytesize.between?(3, 4098)

    expression = expression[1...-1]
    expression = expression.dup.force_encoding(Encoding::UTF_8)
    return unless expression.valid_encoding?
    return if expression.match?(/[\s\p{Cc}"\\]/)
    if fields["op"] == "delete"
      return if fields.key?("tcontext")
    else
      return unless fields["tcontext"].to_s.match?(/\Asystem_u:object_r:[A-Za-z_][A-Za-z0-9_]*:(?:s0)?\z/)
    end
    { "operation" => fields["op"], "expression" => expression, "file_selector" => fields["ftype"],
      "target_context" => fields["tcontext"], "selinux_type" => fields["tcontext"]&.split(":")&.[](2), "success" => fields["res"] == "success" }
  end

  def self.port_record?(payload)
    payload.scan(/(?:\A|\s)msg='([^']*)'(?:\s|\z)/).any? do |body|
      body.first == "resrc=port" || body.first.start_with?("resrc=port ")
    end
  end

  def self.port_change(payload)
    fields = user_change_fields(payload)
    return unless fields
    return unless fields["resrc"] == "port" && %w[add modify delete].include?(fields["op"]) &&
      %w[6 17].include?(fields["proto"]) && fields["lport"].to_s.match?(/\A[0-9]+(?:-[0-9]+)?\z/) &&
      (fields.keys & %w[success old_tcontext old_type tglob ftype sglob]).empty?

    first, last = fields["lport"].split("-", 2).map(&:to_i)
    last ||= first
    return unless first.between?(1, 65535) && last.between?(first, 65535)
    if fields["op"] == "delete"
      return if fields.key?("tcontext")
    else
      return unless fields["tcontext"].to_s.match?(/\Asystem_u:object_r:[A-Za-z_][A-Za-z0-9_]*:s0\z/)
    end
    { "operation" => fields["op"], "protocol" => fields["proto"] == "6" ? "tcp" : "udp",
      "start" => first, "end" => last, "target_context" => fields["tcontext"],
      "selinux_type" => fields["tcontext"]&.split(":")&.[](2), "success" => fields["res"] == "success" }
  end

  def self.user_change_fields(payload)
    messages = payload.scan(/(?:\A|\s)msg='([^']*)'(?:\s|\z)/)
    return unless messages.one? && messages.sole.first.match?(/\A(?:[A-Za-z_]+=(?:"(?:\\.|[^"])*"|[^\s"]*)(?:\s+|\z))+\z/)

    fields = {}
    messages.sole.first.scan(/(?:\A|\s)([A-Za-z_]+)=("(?:\\.|[^"])*"|[^\s"]*)/).each do |key, value|
      return if fields.key?(key)

      fields[key] = value
    end
    fields
  end

  def self.effective_context_observations(observations, invalidated_fields)
    return Array(observations) unless Array(invalidated_fields).include?("file_context_mappings")

    Array(observations).map do |item|
      item["kind"] == "expected_context" ? item.merge("status" => "unavailable", "reason" => "file_context_mapping_boundary") : item.merge("expected_status" => "unknown")
    end
  end

  def effective_file_context_observations
    self.class.effective_context_observations(file_context_observations, checkpoint_invalidated_fields)
  end
end
