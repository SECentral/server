class PolicyArtifactsController < ApplicationController
  include AgentAuthentication

  before_action :authenticate_agent!, :resolve_ingestion_organization!

  rescue_from ActiveRecord::RecordNotFound do
    render json: { error: { code: "not_found", message: "Host not found" } }, status: :not_found
  end

  def create
    return head :content_too_large if request.content_length.to_i > PolicyArtifact::MAX_BYTES

    host = @ingestion_organization.hosts.find_by!(external_id: request.headers["X-SECentral-Host-ID"])
    bytes = request.body.read(PolicyArtifact::MAX_BYTES + 1)
    return head :content_too_large if bytes.bytesize > PolicyArtifact::MAX_BYTES

    PolicyArtifactIngestion.call(host: host, policy_identity: params[:policy_identity], bytes: bytes)
    head :created
  rescue PolicyArtifactIngestion::InvalidArtifact => error
    render json: { error: { code: "invalid_policy_artifact", message: error.message } }, status: :unprocessable_content
  rescue PolicyArtifactIngestion::HostIdentityMismatch
    render json: { error: { code: "policy_identity_mismatch", message: "Host has not reported this exact policy identity" } }, status: :conflict
  end
end
