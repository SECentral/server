require_relative "boot"

require "rails"
# Pick the frameworks you want:
require "active_model/railtie"
require "active_job/railtie"
require "active_record/railtie"
# require "active_storage/engine"
require "action_controller/railtie"
# require "action_mailer/railtie"
# require "action_mailbox/engine"
# require "action_text/engine"
require "action_view/railtie"
require "action_cable/engine"

# Require the gems listed in Gemfile, including any gems
# you've limited to :test, :development, or :production.
Bundler.require(*Rails.groups)

module SecentralServer
  class Application < Rails::Application
    # Initialize configuration defaults for originally generated Rails version.
    config.load_defaults 8.1

    # Please, add to the `ignore` list any other `lib` subdirectories that do
    # not contain `.rb` files, or that should not be reloaded or eager loaded.
    # Common ones are `templates`, `generators`, or `middleware`, for example.
    config.autoload_lib(ignore: %w[tasks])

    # Configuration for the application, engines, and railties goes here.
    #
    # These settings can be overridden in specific environments using the files
    # in config/environments, which are processed later.
    #
    # config.time_zone = "Central Time (US & Canada)"
    # config.eager_load_paths << Rails.root.join("extras")

    config.api_only = false

    # Content Security Policy: deny-by-default, same-origin only. The Vite SPA
    # build emits no inline scripts/styles, no external origins, no eval, and
    # no data: URIs, so a fully restrictive policy is sufficient.
    config.content_security_policy do |policy|
      policy.default_src :self
      policy.base_uri :self
      policy.object_src :none
      policy.frame_ancestors :none
      policy.form_action :self
      policy.script_src :self
      policy.style_src :self
      policy.img_src :self
      policy.font_src :self
      policy.connect_src :self
    end
    # Enforce (not report-only) on every response.
    config.content_security_policy_report_only = false
    # SECentral loads no scripts, so no CSP nonce is required. The csp_meta_tag in
    # the layouts is therefore unnecessary and has been removed.

    config.x.agent_reporting = ActiveSupport::OrderedOptions.new
    config.x.agent_reporting.stale_after = 15.minutes
    config.x.agent_reporting.offline_after = 60.minutes
  end
end
