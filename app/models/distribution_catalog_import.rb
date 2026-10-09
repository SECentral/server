class DistributionCatalogImport < ApplicationRecord
  belongs_to :distribution_catalog_revision
  validates :source_kind, inclusion: { in: %w[unspecified administrative_cli operator_upload] }

  before_update { raise ActiveRecord::ReadOnlyRecord, self }
  before_destroy { raise ActiveRecord::ReadOnlyRecord, self }
end
