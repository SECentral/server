require "spec_helper"
require "fileutils"
require "open3"
require "tmpdir"

RSpec.describe "Architecture rules" do
  it "accepts reads and persistence workflows and rejects HTTP coupling and query writes" do
    Dir.mktmpdir("secentral-architecture") do |directory|
      FileUtils.cp(File.expand_path("../Archspec.rb", __dir__), directory)
      %w[controllers models services queries jobs].each do |component|
        FileUtils.mkdir_p(File.join(directory, "app", component))
      end
      File.write(File.join(directory, "app/controllers/example_controller.rb"), "class ExampleController; end")
      query = File.join(directory, "app/queries/example_query.rb")
      File.write(query, "class ExampleQuery; def call; Record.where(active: true); end; end")
      File.write(File.join(directory, "app/services/example_service.rb"), "class ExampleService; def call; Record.create!; end; end")

      executable = Gem.bin_path("archspec", "archspec")
      output, status = Open3.capture2e(Gem.ruby, executable, "check", chdir: directory)
      expect(status.success?).to be(true), output

      %w[models services queries jobs].each do |component|
        path = File.join(directory, "app", component, "forbidden.rb")
        File.write(path, "class Forbidden; def call; ExampleController; params; end; end")
        output, status = Open3.capture2e(Gem.ruby, executable, "check", chdir: directory)
        expect(status.success?).to be(false), output
        expect(output).to include("app/#{component}/forbidden.rb", "dependencies.forbid", "methods.forbid"), output
        File.delete(path)
      end

      %w[update_all delete_by destroy_by touch toggle toggle! increment increment! decrement decrement! insert insert! upsert].each do |method|
        File.write(query, "class ExampleQuery; def call; Record.#{method}; end; end")
        output, status = Open3.capture2e(Gem.ruby, executable, "check", chdir: directory)
        expect(status.success?).to be(false), "#{method} was allowed\n#{output}"
        expect(output).to include("app/queries/example_query.rb", method, "methods.forbid"), output
      end

      File.write(query, "class ExampleQuery; def call; Record.where(active: true); end; end")
      File.write(File.join(directory, "app/jobs/example_job.rb"), "class ExampleJob; def perform; Record.update_all(active: false); end; end")
      output, status = Open3.capture2e(Gem.ruby, executable, "check", chdir: directory)
      expect(status.success?).to be(true), output
    end
  end
end
