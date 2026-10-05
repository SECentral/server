RSpec.configure do |config|
  config.example_status_persistence_file_path = "tmp/rspec-examples.txt"
  config.disable_monkey_patching!
  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end
end
