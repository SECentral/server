module AgentAuthentication
  extend ActiveSupport::Concern

  private

  def authenticate_agent!
    key = request.authorization.to_s[/\ABearer ([^\s]+)\z/, 1]
    configured_key = ENV.fetch("SECENTRAL_INGESTION_KEY", "")
    unless key && configured_key.present? && ActiveSupport::SecurityUtils.secure_compare(configured_key, key)
      head :unauthorized
    end
  end

  def resolve_ingestion_organization!
    @ingestion_organization = Organization.sole
  rescue ActiveRecord::RecordNotFound, ActiveRecord::SoleRecordExceeded
    render json: { error: { code: "ingestion_unavailable", message: "Ingestion requires exactly one organization" } }, status: :service_unavailable
  end
end
