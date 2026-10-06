class Host < ApplicationRecord
  STALE_AFTER = 15.minutes

  belongs_to :organization
  has_many :host_snapshots, dependent: :restrict_with_exception
  has_many :host_snapshot_observations, -> { order(last_received_at: :desc, id: :desc) }, dependent: :restrict_with_exception
  has_one :current_state_observation, -> { order(last_received_at: :desc, id: :desc) }, class_name: "HostSnapshotObservation"
  has_many :raw_events, dependent: :restrict_with_exception
  has_many :agent_installations, foreign_key: :bound_host_id, dependent: :nullify
  has_many :occurrences, dependent: :restrict_with_exception

  validates :external_id, presence: true, uniqueness: { scope: :organization_id }

  def self.find_for_ingestion!(organization, external_id)
    organization.hosts.find_or_create_by!(external_id: external_id)
  rescue ActiveRecord::RecordNotUnique, ActiveRecord::RecordInvalid
    organization.hosts.find_by!(external_id: external_id)
  end

  def stale?
    last_seen_at.nil? || last_seen_at < STALE_AFTER.ago
  end

  def current_configuration?
    current_state_observation.present? && !current_state_observation.stale?
  end

  def current_snapshot
    current_state_observation&.host_snapshot
  end

  def current_policy_identity
    policy_identity_for(current_state_observation)
  end

  def policy_identity_for(observation)
    return unless observation

    snapshot = observation.host_snapshot
    details = snapshot.details
    transition = raw_events.where(boot_id: details["boot_id"])
      .where("transition_type IN ('policy_load', 'boolean_change', 'port_change') OR (category = 'avc' AND checkpoint_invalidated_fields ? 'policy_identity')")
      .where("audit_timestamp >= ?", observation.last_observed_at).exists?
    return if transition

    details.dig("selinux", "policy_identity")
  end

  def enforcement_for(observation = current_state_observation)
    return unless observation

    details = observation.host_snapshot.details
    unsafe = raw_events.where(boot_id: details["boot_id"])
      .where("audit_timestamp >= ?", observation.last_observed_at)
      .where("transition_type = 'enforcement_change' OR (category = 'avc' AND checkpoint_invalidated_fields ? 'enforcement')").exists?
    unsafe ? "unknown" : details.dig("selinux", "enforcement")
  end

  def port_inventory_for(observation = current_state_observation)
    return { "status" => "unknown", "mappings" => [] } unless observation

    details = observation.host_snapshot.details
    unsafe = raw_events.where(boot_id: details["boot_id"])
      .where("audit_timestamp >= ?", observation.last_observed_at)
      .where("transition_type IN ('port_change', 'policy_load') OR (category = 'avc' AND checkpoint_invalidated_fields ? 'ports')").exists?
    unsafe ? { "status" => "unknown", "mappings" => [] } : details.dig("selinux", "policy", "port_inventory") || { "status" => "unknown", "mappings" => [] }
  end
end
