class CatalogManagement < ApplicationRecord
  belongs_to :distribution_catalog_revision
  has_many :catalog_management_changes, -> { order(:id) }, dependent: :restrict_with_exception

  validates :display_name, presence: true, length: { maximum: 120 }, format: { with: /\A[^\p{Cc}]+\z/ }
  validates :lifecycle, inclusion: { in: %w[active archived] }
  attr_readonly :distribution_catalog_revision_id
  before_destroy(prepend: true) { raise ActiveRecord::ReadOnlyRecord, self }

  # Row locking serializes management writes; each operation changes only its field.
  def change!(changed_by:, **attributes)
    with_lock do
      previous = { previous_display_name: display_name, previous_lifecycle: lifecycle }
      assign_attributes(attributes)
      self.display_name = display_name.strip if display_name.is_a?(String)
      if changed?
        save!
        catalog_management_changes.create!(**previous, display_name: display_name, lifecycle: lifecycle, changed_by: changed_by)
      end
    end
    self
  end
end
