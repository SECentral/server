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
      File.write(File.join(directory, "app/jobs/example_job.rb"), "class ExampleJob; def perform; Record.update_all(active: false); end; end")

      executable = Gem.bin_path("archspec", "archspec")
      output, status = Open3.capture2e(Gem.ruby, executable, "check", chdir: directory)
      expect(status.success?).to be(true), output

      %w[models services queries jobs].each do |component|
        path = File.join(directory, "app", component, "forbidden.rb")
        File.write(path, "class Forbidden; def call; ExampleController; params; end; end")
      end
      methods = %w[update_all delete_by destroy_by touch toggle toggle! increment increment! decrement decrement! insert insert! upsert]
      methods.each_with_index do |method, index|
        File.write(File.join(directory, "app/queries/write_#{index}.rb"), "class Write#{index}; def call; Record.#{method}; end; end")
      end

      output, status = Open3.capture2e(Gem.ruby, executable, "check", chdir: directory)
      expect(status.success?).to be(false), output
      diagnostics = output.split(/(?=^\[error\])/)
      %w[models services queries jobs].each do |component|
        violations = diagnostics.select { |diagnostic| diagnostic.include?("app/#{component}/forbidden.rb:") }.join
        expect(violations).to include("dependencies.forbid", "methods.forbid"), output
      end
      methods.each_with_index do |method, index|
        violations = diagnostics.select { |diagnostic| diagnostic.include?("app/queries/write_#{index}.rb:") }.join
        expect(violations).to include(method, "methods.forbid"), output
      end
    end
  end

  it "checks concern callbacks and Rake task syntax" do
    Dir.mktmpdir("secentral-architecture") do |directory|
      FileUtils.cp(File.expand_path("../Archspec.rb", __dir__), directory)
      FileUtils.mkdir_p(File.join(directory, "app/services"))
      FileUtils.mkdir_p(File.join(directory, "lib/tasks"))
      File.write(File.join(directory, "app/services/http_concern.rb"), <<~RUBY)
        module HttpConcern
          extend ActiveSupport::Concern
          included do
            params
          end
        end
      RUBY
      File.write(File.join(directory, "app/services/example.rb"), <<~RUBY)
        class ExampleService
          include HttpConcern
        end
      RUBY
      task = File.join(directory, "lib/tasks/example.rake")
      File.write(task, "task :example do\nend\n")

      executable = Gem.bin_path("archspec", "archspec")
      output, status = Open3.capture2e(Gem.ruby, executable, "check", chdir: directory)
      expect(status.success?).to be(false), output
      expect(output).to include("methods.forbid", "params", "app/services/http_concern.rb")

      File.write(File.join(directory, "app/services/example.rb"), "class ExampleService; end\n")
      File.write(task, "task :example do\n")
      output, status = Open3.capture2e(Gem.ruby, executable, "check", chdir: directory)
      expect(status.success?).to be(false), output
      expect(output).to include("lib/tasks/example.rake")
    end
  end
end
