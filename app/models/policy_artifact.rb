class PolicyArtifact < ApplicationRecord
  MAX_BYTES = 16 * 1024 * 1024
  IDENTITY_FORMAT = /\Asha256:[0-9a-f]{64}\z/

  validates :policy_identity, format: { with: IDENTITY_FORMAT }
  validates :artifact_size, numericality: { greater_than: 0, less_than_or_equal_to: MAX_BYTES }
end
