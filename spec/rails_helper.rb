ENV["RAILS_ENV"] ||= "test"
require_relative "../config/environment"
require "rspec/rails"
require_relative "spec_helper"

abort("The Rails environment is running in production mode!") if Rails.env.production?

ENV["ADMIN_USERNAME"] = "test-admin"
ENV["ADMIN_PASSWORD_DIGEST"] = BCrypt::Password.create("test-password").to_s
ENV["SECENTRAL_INGESTION_KEY"] = "test-ingestion-key"

module OperatorAuthenticationSpecHelpers
  def sign_in_operator
    post "/api/v1/sessions", params: { username: "test-admin", password: "test-password" }
    expect(response).to have_http_status(:created)
  end

  # Clears the rack-test session, which persists across examples in a file.
  def sign_out_operator
    delete "/api/v1/sessions"
  end
end

RSpec.configure do |config|
  config.use_transactional_fixtures = false
  config.infer_spec_type_from_file_location!
  config.filter_rails_from_backtrace!
  config.include OperatorAuthenticationSpecHelpers, type: :request
end
