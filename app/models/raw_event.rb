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
  POLICY_TRANSITIONS = %w[policy_load boolean_change].freeze
  STATE_TRANSITIONS = (POLICY_TRANSITIONS + %w[enforcement_change]).freeze
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
    return "unknown" if checkpoint_invalidated_fields.include?("enforcement") || !snapshot

    snapshot.details.dig("selinux", "enforcement") || "unknown"
  end
end
