class AddCatalogImportSource < ActiveRecord::Migration[8.1]
  def change
    add_column :distribution_catalog_imports, :imported_by, :string
    add_column :distribution_catalog_imports, :source_kind, :string, null: false, default: "unspecified"
    add_check_constraint :distribution_catalog_imports, "source_kind IN ('unspecified', 'administrative_cli', 'operator_upload')", name: "catalog_import_source_kind"
  end
end
