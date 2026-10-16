class Api::V1::ConfigurationsController < Api::V1::BaseController
  def show
    family = params[:family].presence || "overview"
    identity = params[:policy_identity].presence
    protocol = params[:protocol].presence
    limit = PageSize.parse(params[:limit])
    page = [Integer(params[:page] || 1), 1].max
    raise ArgumentError, "search too long" if params[:q].to_s.length > 200

    unless ConfigurationQuery::FAMILIES.include?(family)
      return render json: { error: { code: "invalid_value", message: "Unknown configuration family" } }, status: :unprocessable_content
    end
    if identity && !identity.match?(ConfigurationQuery::POLICY_IDENTITY_FORMAT)
      return render json: { error: { code: "invalid_value", message: "Invalid policy identity" } }, status: :unprocessable_content
    end
    if protocol && (family != "ports" || !%w[tcp udp].include?(protocol))
      return render json: { error: { code: "invalid_value", message: "Invalid port protocol" } }, status: :unprocessable_content
    end

    render json: ConfigurationQuery.call(family: family, policy_identity: identity, page: page, limit: limit, query: params[:q], protocol: protocol)
  rescue PageSize::Invalid, ArgumentError
    render json: { error: { code: "invalid_value", message: "Invalid page, page size, or search" } }, status: :unprocessable_content
  end
end
