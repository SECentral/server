class Api::V1::UngroupableEventsController < Api::V1::BaseController
  def index
    events = ungroupable_occurrences.order(occurred_at: :desc).to_a
    render json: {
      events: events.map { |occurrence| serialize_event(occurrence) },
      total_count: events.size
    }
  end

  private

  def ungroupable_occurrences
    scope = Occurrence.includes(:host, :normalized_denial).joins(:normalized_denial).where(normalized_denials: { status: "ungroupable" })
    scope = scope.where(host_id: params[:host_id].presence) if params[:host_id].present?
    scope
  end

  def serialize_event(occurrence)
    {
      id: occurrence.id,
      host: { id: occurrence.host.id, hostname: occurrence.host.hostname },
      missing: Array(occurrence.normalized_denial.details.fetch("missing", [])),
      occurred_at: occurrence.occurred_at
    }
  end
end
