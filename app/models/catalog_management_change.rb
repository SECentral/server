class CatalogManagementChange < ApplicationRecord
  belongs_to :catalog_management
  validates :changed_by, presence: true
  before_update { raise ActiveRecord::ReadOnlyRecord, self }
  before_destroy { raise ActiveRecord::ReadOnlyRecord, self }
end
