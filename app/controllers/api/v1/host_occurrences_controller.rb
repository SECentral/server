class Api::V1::HostOccurrencesController < Api::V1::BaseController
  def index
    host = Host.find(params[:id])
    limit = params.fetch(:limit, 50).to_i
    limit = 50 if limit > 50 || limit < 1

    relation = host.occurrences
      .includes(:issue, :host_snapshot, normalized_denial: {}, raw_event: { raw_audit_records: {} })
      .order(occurred_at: :desc, id: :desc)
    if params.key?(:page)
      unless params[:page].to_s.match?(/\A[1-9]\d*\z/) && params[:before].blank?
        render json: { error: { code: "invalid_value", message: "Page must be a positive integer and cannot be combined with before" } }, status: :unprocessable_content
        return
      end
      total = host.occurrences.count
      total_pages = (total / limit.to_f).ceil
      page = [params[:page].to_i, [total_pages, 1].max].min
      relation = relation.offset((page - 1) * limit)
    end
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
    next_cursor = occurrences.size == limit ? encode_cursor(occurrences.last.occurred_at, occurrences.last.id) : nil
    render json: {
      occurrences: occurrences.map { |occurrence| OccurrenceDetailSerializer.call(occurrence, guidance: occurrence_guidance(occurrence)) },
      meta: { next_cursor: next_cursor }.merge(page ? { page: page, page_size: limit, total: total, total_pages: total_pages } : {})
    }
  end

  private

  def occurrence_guidance(occurrence)
    return nil unless occurrence.issue

    guidance = InvestigationGuidance.call(issue: occurrence.issue, occurrence: occurrence)
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
