class Api::V1::HostsController < Api::V1::BaseController
  def index
    filters = params.permit(:os_id, :policy_type, :kernel_policy_version, :enforcement, :agent_version, :status, :host_id, :configuration_family, :configuration_status).to_h
    if filters["configuration_family"].present? || filters["configuration_status"].present?
      family = filters["configuration_family"]
      state = filters["configuration_status"]
      unless HostListQuery::CONFIGURATION_STATES.fetch(family, []).include?(state)
        return render json: { error: { code: "invalid_value", message: "Invalid configuration coverage filter" } }, status: :unprocessable_content
      end
    end
    result = HostListQuery.new(filters: filters, page: params[:page], limit: params[:limit]).call
    counts = host_counts(result.hosts)
    render json: {
      hosts: result.hosts.map { |host| HostSerializer.call(host, counts: counts.fetch(host.id)) },
      summary: { agent_state_counts: result.agent_state_counts, total: result.total_count },
      meta: {
        page: result.page,
        page_size: result.page_size,
        total: result.total_count,
        total_pages: (result.total_count / result.page_size.to_f).ceil
      }
    }
  end

  def show
    host = current_organization.hosts.includes(:agent_installations, current_state_observation: :host_snapshot).find(params[:id])
    render json: { host: HostSerializer.call(host, counts: host_counts([host]).fetch(host.id), include_snapshot: true) }
  end

  private

  def host_counts(hosts)
    ids = hosts.map(&:id)
    since = 24.hours.ago
    issue_counts = Occurrence.where(host_id: ids, issue_id: Issue.where(status: "open")).distinct.group(:host_id).count(:issue_id)
    # ponytail: scan retained decisions for the page's hosts; move to SQL aggregation if history size makes this costly.
    rows = Occurrence.where(host_id: ids).joins(:normalized_denial)
      .pluck(:host_id, :raw_event_id, ObservationSummary::DETAILS_SQL, :occurred_at).group_by(&:first)
    ids.index_with do |id|
      host_rows = rows.fetch(id, [])
      observations = ObservationSummary.from_rows(host_rows.map { |row| [row[1], row[2]] })
      recent = ObservationSummary.from_rows(host_rows.select { |row| row[3] >= since }.map { |row| [row[1], row[2]] })
      { active_issues: issue_counts.fetch(id, 0), avcs_24h: recent[:occurrences], total_events: observations[:occurrences],
        observations: observations, observations_24h: recent }
    end
  end
end
