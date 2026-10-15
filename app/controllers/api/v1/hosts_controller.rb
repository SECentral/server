class Api::V1::HostsController < Api::V1::BaseController
  def index
    filters = params.permit(:os_id, :policy_type, :kernel_policy_version, :enforcement, :agent_version, :status, :host_id).to_h
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
    total_counts = Occurrence.where(host_id: ids).group(:host_id).count
    avc_counts = Occurrence.where(host_id: ids, occurred_at: 24.hours.ago..).group(:host_id).count
    issue_counts = Occurrence.where(host_id: ids, issue_id: Issue.where(status: "open")).distinct.group(:host_id).count(:issue_id)
    ids.index_with do |id|
      { active_issues: issue_counts.fetch(id, 0), avcs_24h: avc_counts.fetch(id, 0), total_events: total_counts.fetch(id, 0) }
    end
  end
end
