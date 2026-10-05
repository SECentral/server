require "rails_helper"
require "rake"

Rails.application.load_tasks unless Rake::Task.task_defined?("secentral:catalog:validate")

RSpec.describe "SECentral catalog tasks" do
  let(:file) { Rails.root.join("spec/fixtures/catalogs/v3.json").to_s }

  around do |example|
    DistributionCatalogImport.delete_all
    DistributionCatalogBoolean.delete_all
    DistributionCatalogPort.delete_all
    DistributionCatalogRevision.delete_all
    example.run
    DistributionCatalogImport.delete_all
    DistributionCatalogBoolean.delete_all
    DistributionCatalogPort.delete_all
    DistributionCatalogRevision.delete_all
  end

  it "validates and imports a V3 artifact" do
    validate = Rake::Task["secentral:catalog:validate"]
    validate.reenable
    expect { validate.invoke(file) }.to output(/Valid: sha256:3d8d/).to_stdout

    import = Rake::Task["secentral:catalog:import"]
    import.reenable
    expect { import.invoke(file) }.to output(/Imported: sha256:3d8d/).to_stdout
    expect(DistributionCatalogRevision.count).to eq(1)
    expect(DistributionCatalogImport.count).to eq(1)
  end
end
