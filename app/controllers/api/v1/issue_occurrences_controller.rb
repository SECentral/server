class Api::V1::IssueOccurrencesController < Api::V1::BaseController
  def index
    issue = current_organization.issues.find(params[:id])
    scope = params[:signature_id].present? ? issue.signatures.find(params[:signature_id]).occurrences : issue.occurrences
    return render_summary_page(scope) if %w[summary activity].include?(params[:view])
    limit = params.fetch(:limit, 50).to_i
    limit = 50 if limit > 50 || limit < 1

    relation = scope
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
    issue = current_organization.issues.find(params[:id])
    occurrence = issue.occurrences.unscope(where: :superseded_at).includes(:host, :host_snapshot, :normalized_denial, raw_event: :raw_audit_records).find(params[:occurrence_id])
    render json: OccurrenceDetailSerializer.call(occurrence, guidance: occurrence_guidance(issue, occurrence))
  end

  private

  def render_summary_page(scope)
    # ponytail: offset pages can shift during ingestion; use snapshot cursors if stable browsing under sustained writes is needed.
    page_size = PageSize.parse(params[:limit], default: 10, max: 50)
    total = scope.count
    pages = [ (total / page_size.to_f).ceil, 1 ].max
    page = params.fetch(:page, 1).to_i.clamp(1, pages)
    occurrences = scope.includes(:host, :normalized_denial)
      .order(occurred_at: :desc, id: :desc).offset((page - 1) * page_size).limit(page_size)
    occurrences = occurrences.includes(raw_event: :raw_audit_records) if params[:view] == "activity"
    result = {
      occurrences: occurrences.map do |occurrence|
        denial = occurrence.normalized_denial
        evidence = denial.details.to_h.fetch("target_evidence", {})
        paths = Array(evidence["filesystem_paths"])
        names = Array(evidence["object_names"])
        protocol = { "tcp_socket" => "TCP", "udp_socket" => "UDP" }[denial.target_class]
        ports = if protocol && denial.permissions.include?("name_bind")
          IssueIntelligence.bind_ports(denial.details)
        elsif protocol == "TCP" && denial.permissions.include?("name_connect")
          IssueIntelligence.destination_ports(denial.details)
        else
          []
        end
        resource = ports.one? ? "#{protocol}/#{ports.first}" : ports.any? ? "Multiple #{protocol} ports" : paths.first || names.first
        syscalls = Array(denial.details["syscall_evidence"])
        outcome = if syscalls.any? { |syscall| %w[no false 0].include?(syscall["success"].to_s) }
          "failed"
        elsif syscalls.any? && syscalls.all? { |syscall| %w[yes true 1].include?(syscall["success"].to_s) }
          "succeeded"
        else
          "unknown"
        end
        { id: occurrence.id, occurred_at: occurrence.occurred_at, issue_signature_id: occurrence.issue_signature_id,
          enforcement_mode: denial.details.fetch("enforcement_mode", "unknown"), syscall_outcome: outcome,
          host: { id: occurrence.host_id, hostname: occurrence.host.hostname },
          resource: resource, absolute_path: paths.present?,
          target_type: denial.target_type, permissions: denial.permissions }
      end,
      meta: { page: page, page_size: page_size, total: total, total_pages: pages }
    }
    if params[:view] == "activity"
      result[:activity_groups] = IssueActivityGroups.call(occurrences)
      result[:activity_scope] = "current_page"
    end
    render json: result
  end

  def occurrence_guidance(issue, occurrence)
    return nil if occurrence.superseded_at

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
