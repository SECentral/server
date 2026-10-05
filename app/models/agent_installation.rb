class AgentInstallation < ApplicationRecord
  REPORTING_STATES = %w[reporting stale offline].freeze

  belongs_to :organization
  belongs_to :bound_host, class_name: "Host", optional: true
  has_many :raw_events, dependent: :restrict_with_exception
  has_many :host_snapshot_observations, dependent: :restrict_with_exception

  validates :name, presence: true

  def stale?
    reporting_state == "stale"
  end

  def reporting_state(at: Time.current)
    return "offline" if last_seen_at.nil?

    age = at - last_seen_at
    return "offline" if age >= reporting_threshold(:offline_after)
    return "stale" if age >= reporting_threshold(:stale_after)

    "reporting"
  end

  private

  def reporting_threshold(name)
    Rails.application.config.x.agent_reporting.public_send(name).to_f
  end
end
