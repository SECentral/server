class AddCatalogImportComparisonReport < ActiveRecord::Migration[8.1]
  def change
    # Existing evidence has no recorded comparison; never backfill today's basis.
    add_column :distribution_catalog_imports, :comparison_report, :jsonb
  end
end
