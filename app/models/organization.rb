class Organization < ApplicationRecord
  has_many :agent_installations, dependent: :restrict_with_exception
  has_many :hosts, dependent: :restrict_with_exception
  has_many :raw_events, dependent: :restrict_with_exception
  has_many :issues, dependent: :restrict_with_exception
  has_many :occurrences, dependent: :restrict_with_exception

  validates :name, presence: true, uniqueness: true
end
