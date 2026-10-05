class HostSnapshot < ApplicationRecord
  belongs_to :host
  has_many :raw_events, dependent: :restrict_with_exception
  has_many :occurrences, dependent: :restrict_with_exception
  has_many :host_snapshot_observations, dependent: :restrict_with_exception

  validate :details_are_present

  private

  def details_are_present
    errors.add(:details, "can't be blank") unless details.is_a?(Hash)
  end
end
