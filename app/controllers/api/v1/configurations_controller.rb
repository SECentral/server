class Api::V1::ConfigurationsController < Api::V1::BaseController
  def show
    family = params[:family].presence || "overview"
    identity = params[:policy_identity].presence

    unless ConfigurationQuery::FAMILIES.include?(family)
      return render json: { error: { code: "invalid_value", message: "Unknown configuration family" } }, status: :unprocessable_entity
    end
    if identity && !identity.match?(ConfigurationQuery::POLICY_IDENTITY_FORMAT)
      return render json: { error: { code: "invalid_value", message: "Invalid policy identity" } }, status: :unprocessable_entity
    end

    render json: ConfigurationQuery.call(family: family, policy_identity: identity)
  end
end
