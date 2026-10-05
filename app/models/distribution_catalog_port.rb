class DistributionCatalogPort < ApplicationRecord
  belongs_to :distribution_catalog_revision

  before_update { raise ActiveRecord::ReadOnlyRecord, self }
  before_destroy { raise ActiveRecord::ReadOnlyRecord, self }
end
