require "rails_helper"
require "rake"

Rails.application.load_tasks unless Rake::Task.task_defined?("secentral:catalog:validate")

RSpec.describe "SECentral catalog tasks" do
  let(:file) { Rails.root.join("spec/fixtures/catalogs/v3.json").to_s }

  around do |example|
    CatalogPolicyArtifact.delete_all
    DistributionCatalogImport.delete_all
    DistributionCatalogBoolean.delete_all
    DistributionCatalogPort.delete_all
    DistributionCatalogRevision.delete_all
    example.run
    CatalogPolicyArtifact.delete_all
    PolicyArtifact.delete_all
    DistributionCatalogImport.delete_all
    DistributionCatalogBoolean.delete_all
    DistributionCatalogPort.delete_all
    DistributionCatalogRevision.delete_all
  end

  it "attaches an offline companion only through explicit local administrative input" do
    require "tempfile"
    bytes = "administrative exact policy".b
    document = JSON.parse(File.binread(file))
    document["catalog"]["policy"]["loaded_policy_digest"] = "sha256:#{Digest::SHA256.hexdigest(bytes)}"
    document["content_digest"] = "sha256:#{Digest::SHA256.hexdigest(DistributionCatalogCanonicalizer.call(document['catalog']))}"
    revision = ImportDistributionCatalog.call(artifact: DistributionCatalogArtifact.new(JSON.generate(document))).revision
    task = Rake::Task["secentral:catalog:attach_policy"]
    Tempfile.create("policy-companion") do |input|
      input.binmode
      input.write(bytes)
      input.flush
      expect { task.execute(Rake::TaskArguments.new(%i[revision_id file acquisition_basis], [revision.id.to_s, input.path, "Offline reference capture"])) }.to output(/expected=#{revision.loaded_policy_digest} actual=#{revision.loaded_policy_digest}/).to_stdout
      expect(CatalogPolicyArtifact.count).to eq(1)
      expect(revision.reload.reference_policy_artifact[:status]).to eq("available")
    end
    expect { expect { task.execute(Rake::TaskArguments.new([], [])) }.to raise_error(SystemExit) }.to output(/requires/).to_stderr
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

  it "fails repository source CI when there are zero reviewed catalog artifacts" do
    allow(CatalogDistributionSource).to receive(:verify).with(Rails.root.join("catalogs")).and_return(CatalogDistributionSource::Result.new(0))
    expect do
      expect { Rake::Task["secentral:catalog:verify_distribution"].execute }.to raise_error(SystemExit) { |error| expect(error.status).to eq(1) }
    end.to output(/at least one reviewed artifact/).to_stderr
  end

  it "accepts a repository catalog count greater than one" do
    allow(CatalogDistributionSource).to receive(:verify).with(Rails.root.join("catalogs")).and_return(CatalogDistributionSource::Result.new(3))
    expect { Rake::Task["secentral:catalog:verify_distribution"].execute }.to output(/supported=3/).to_stdout
  end
end
