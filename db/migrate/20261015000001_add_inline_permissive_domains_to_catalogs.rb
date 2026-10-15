class AddInlinePermissiveDomainsToCatalogs < ActiveRecord::Migration[8.1]
  def change
    add_column :distribution_catalog_revisions, :effective_permissive_domains, :jsonb
  end
end
