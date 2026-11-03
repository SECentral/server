class MetricsController < ApplicationController
  before_action :authenticate_metrics!

  def show
    result = DomainMetricsQuery.new.call
    render plain: PrometheusMetricsExporter.new.call(result),
      content_type: "text/plain; version=0.0.4; charset=utf-8"
  end

  private

  def authenticate_metrics!
    response.headers["Cache-Control"] = "no-store"
    configured = ENV.fetch("SECENTRAL_METRICS_TOKEN", "")
    return head :not_found if configured.blank?

    token = request.authorization.to_s[/\ABearer +([^\s]+)\z/i, 1]
    return if token && ActiveSupport::SecurityUtils.secure_compare(configured, token)

    response.headers["WWW-Authenticate"] = 'Bearer realm="metrics"'
    head :unauthorized
  end
end
