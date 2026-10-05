class NormalizedDenial < ApplicationRecord
  belongs_to :raw_event
  has_one :occurrence, dependent: :restrict_with_exception

  validates :ordinal, :normalization_version, :status, presence: true
end
