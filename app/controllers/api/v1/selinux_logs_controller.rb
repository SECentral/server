class Api::V1::SelinuxLogsController < Api::V1::BaseController
  def index
    %w[category host_id start end before limit page].each do |key|
      raise ArgumentError, "Invalid #{key}" if params.key?(key) && !params[key].is_a?(String)
    end
    raise ArgumentError, "Expected an array of host IDs" if params.key?(:host_ids) && !(params[:host_ids].is_a?(Array) && params[:host_ids].all? { |id| id.is_a?(String) })
    filters = params.permit(:category, :host_id, :start, :end, :before, :limit, :page, host_ids: []).to_h
    render json: SelinuxLogQuery.new(organization: current_organization, filters: filters).call
  rescue ArgumentError => error
    render json: { error: { code: "invalid_value", message: error.message } }, status: :unprocessable_content
  end

  def hosts
    query = params.fetch(:q, "")
    raise ArgumentError, "Invalid host search" unless query.is_a?(String) && query.bytesize <= 200
    hosts = current_organization.hosts
    hosts = hosts.where("hostname ILIKE :query OR external_id ILIKE :query", query: "%#{Host.sanitize_sql_like(query)}%") if query.present?
    raise ArgumentError, "Expected an array of host IDs" if params.key?(:host_ids) && !(params[:host_ids].is_a?(Array) && params[:host_ids].all? { |id| id.is_a?(String) })
    ids = SelinuxLogQuery.host_ids(params.permit(:host_id, host_ids: []).to_h)
    hosts = hosts.where(id: ids) if ids.any?
    render json: { hosts: hosts.order(:hostname, :id).limit(50).map { |host| host.attributes.slice("id", "hostname", "external_id") } }
  rescue ArgumentError => error
    render json: { error: { code: "invalid_value", message: error.message } }, status: :unprocessable_content
  end
end
