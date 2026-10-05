class HostSnapshotObservation < ApplicationRecord
  belongs_to :host
  belongs_to :host_snapshot
  belongs_to :agent_installation

  validates :first_observed_at, :last_observed_at, :first_received_at, :last_received_at, presence: true

  def stale?(at: Time.current)
    last_received_at < at - Rails.application.config.x.agent_reporting.stale_after
  end
end
