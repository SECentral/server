class Api::V1::IssueOccurrencesController < Api::V1::BaseController
  def index
    issue = Issue.find(params[:id])
    return render_summary_page(issue) if params[:view] == "summary"
    limit = params.fetch(:limit, 50).to_i
    limit = 50 if limit > 50 || limit < 1

    relation = issue.occurrences
      .includes(host: {}, host_snapshot: {}, normalized_denial: {}, raw_event: { raw_audit_records: {} })
      .order(occurred_at: :desc, id: :desc)
    if params[:before].present?
      cursor = begin
        decode_cursor(params[:before])
      rescue ArgumentError
        render json: { error: { code: "invalid_value", message: "Invalid cursor" } }, status: :unprocessable_content
        return
      end
      occurred_at, id = cursor
      relation = relation.where(
        "occurrences.occurred_at < :cursor_at OR (occurrences.occurred_at = :cursor_at AND occurrences.id < :cursor_id)",
        cursor_at: occurred_at, cursor_id: id
      )
    end

    occurrences = relation.limit(limit).to_a
    policy_states = OccurrenceDetailSerializer.policy_states(occurrences)
    next_cursor = occurrences.size == limit ? encode_cursor(occurrences.last.occurred_at, occurrences.last.id) : nil
    render json: {
      occurrences: occurrences.map do |occurrence|
        OccurrenceDetailSerializer.call(occurrence, guidance: occurrence_guidance(issue, occurrence), policy_states: policy_states)
      end,
      meta: { next_cursor: next_cursor }
    }
  end

  def show
    issue = Issue.find(params[:id])
    occurrence = issue.occurrences.includes(:host, :host_snapshot, :normalized_denial, raw_event: :raw_audit_records).find(params[:occurrence_id])
    render json: OccurrenceDetailSerializer.call(occurrence, guidance: occurrence_guidance(issue, occurrence))
  end

  private

  def render_summary_page(issue)
    # ponytail: offset pages can shift during ingestion; use snapshot cursors if stable browsing under sustained writes is needed.
    page_size = 25
    total = issue.occurrences.count
    pages = [ (total / page_size.to_f).ceil, 1 ].max
    page = params.fetch(:page, 1).to_i.clamp(1, pages)
    occurrences = issue.occurrences.includes(:host, :normalized_denial)
      .order(occurred_at: :desc, id: :desc).offset((page - 1) * page_size).limit(page_size)
    render json: {
      occurrences: occurrences.map do |occurrence|
        denial = occurrence.normalized_denial
        evidence = denial.details.to_h.fetch("target_evidence", {})
        paths = Array(evidence["filesystem_paths"])
        names = Array(evidence["object_names"])
        ports = denial.target_class == "tcp_socket" && denial.permissions.include?("name_connect") ? IssueIntelligence.destination_ports(denial.details) : []
        resource = ports.one? ? "TCP/#{ports.first}" : ports.any? ? "Multiple TCP destination ports" : paths.first || names.first
        { id: occurrence.id, occurred_at: occurrence.occurred_at,
          host: { id: occurrence.host_id, hostname: occurrence.host.hostname },
          resource: resource, absolute_path: paths.present?,
          target_type: denial.target_type, permissions: denial.permissions }
      end,
      meta: { page: page, page_size: page_size, total: total, total_pages: pages }
    }
  end

  def occurrence_guidance(issue, occurrence)
    guidance = InvestigationGuidance.call(issue: issue, occurrence: occurrence)
    guidance[:checks].each { |check| check[:command] = InvestigationCommandRenderer.call(check) }
    guidance
  end

  def encode_cursor(occurred_at, id)
    Base64.urlsafe_encode64("#{occurred_at.utc.iso8601(6)}|#{id}", padding: false)
  end

  def decode_cursor(cursor)
    raw = Base64.urlsafe_decode64(cursor)
    time_part, id_part = raw.split("|", 2)
    raise ArgumentError, "invalid cursor" unless id_part&.match?(/\A\d+\z/) && time_part.present?

    [Time.zone.parse(time_part), id_part.to_i]
  end
end
