class HostReportingDay < ApplicationRecord
  EXPECTED_INTERVAL = 5.minutes
  MAX_INTERVAL = 15.minutes
  MICROSECONDS = 1_000_000

  belongs_to :host
  validates :observed_on, presence: true, uniqueness: { scope: :host_id }
  validates :credited_microseconds, numericality: { only_integer: true, greater_than_or_equal_to: 0, less_than_or_equal_to: 86_400 * MICROSECONDS }
end
