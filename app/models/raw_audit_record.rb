class RawAuditRecord < ApplicationRecord
  belongs_to :raw_event

  validates :position, :record_type, :type_name, :audit_timestamp, :sequence, :payload, presence: true
end
