class AddPermissiveDomainAnalysisToPolicyArtifacts < ActiveRecord::Migration[8.1]
  def change
    add_column :policy_artifacts, :permissive_domain_analysis, :jsonb, null: false, default: {}
  end
end
