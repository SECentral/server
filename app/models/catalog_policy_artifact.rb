class CatalogPolicyArtifact < ApplicationRecord
  belongs_to :distribution_catalog_revision
  belongs_to :policy_artifact

  validates :source_kind, inclusion: { in: %w[administrative_cli] }
  validates :acquisition_basis, presence: true, length: { maximum: 500 }, format: { without: /[[:cntrl:]]/ }
  validates :attached_by, length: { maximum: 120 }, format: { without: /[[:cntrl:]]/ }, allow_nil: true
  validate :exact_policy_binding

  before_update { raise ActiveRecord::ReadOnlyRecord, self }
  before_destroy { raise ActiveRecord::ReadOnlyRecord, self }

  private

  def exact_policy_binding
    return unless distribution_catalog_revision && policy_artifact

    policy_artifact.verify_bytes!
    errors.add(:policy_artifact, "does not match catalog loaded-policy digest") unless policy_artifact.policy_identity == distribution_catalog_revision.loaded_policy_digest
  rescue PolicyArtifact::InvalidBytes => error
    errors.add(:policy_artifact, error.message)
  end
end
