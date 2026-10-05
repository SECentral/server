class HostSelinuxActivity
  PAGE_SIZE = 20
  COVERAGE = "Supported SELinux changes observed in this server's audit stream. Absence of an event does not prove that no change occurred.".freeze

  def initialize(host)
    @host = host
  end

  def page(before: nil, occurrence_id: nil, event_id: nil, page: nil)
    relation = supported_events
    unless page.nil?
      raise ArgumentError, "Invalid activity page" unless page.to_s.match?(/\A[1-9]\d*\z/) && [before, occurrence_id, event_id].all?(&:blank?)

      total = relation.count
      total_pages = (total / 10.0).ceil
      number = [page.to_i, [total_pages, 1].max].min
      items = project(relation.order(audit_timestamp: :desc, boot_id: :desc, audit_sequence: :desc).limit(10).offset((number - 1) * 10))
      return response(items, page: number, page_size: 10, total: total, total_pages: total_pages)
    end
    return response(project(relation.where(id: relation.find(event_id).id))) if event_id
    if occurrence_id
      occurrence = @host.occurrences.includes(:raw_event).find(occurrence_id)
      return response([]) if occurrence.host_snapshot_id && !occurrence.raw_event.checkpoint_invalidated_fields.include?("enforcement")

      raw = occurrence.raw_event
      relation = relation.where(transition_type: "enforcement_change") if occurrence.host_snapshot_id
      event = relation.state_transitions.where(boot_id: raw.boot_id)
        .where("(audit_timestamp, audit_sequence) <= (?, ?)", raw.audit_timestamp, raw.audit_sequence)
        .order(audit_timestamp: :desc, audit_sequence: :desc).first
      return response([]) unless event

      item = project(relation.where(id: event.id)).first
      checkpoint = item.dig(:reconciliation, :checkpoint, :event_time)
      return response([]) if checkpoint && raw.audit_timestamp > Time.iso8601(checkpoint)

      return response([item])
    end

    if before.present?
      time, boot, sequence = JSON.parse(Base64.urlsafe_decode64(before))
      raise ArgumentError, "Invalid activity cursor" unless boot.is_a?(String) && boot.present? && sequence.is_a?(Integer)

      relation = relation.where("(audit_timestamp, boot_id, audit_sequence) < (?, ?, ?)", Time.iso8601(time), boot, sequence)
    end
    events = relation.order(audit_timestamp: :desc, boot_id: :desc, audit_sequence: :desc).limit(PAGE_SIZE + 1).to_a
    more = events.size > PAGE_SIZE
    events = events.first(PAGE_SIZE)
    return response([]) if events.empty?
    items = project(supported_events.where(id: events.map(&:id)))
    last = events.last
    cursor = Base64.urlsafe_encode64([last.audit_timestamp.iso8601(6), last.boot_id, last.audit_sequence].to_json, padding: false) if more
    response(items, cursor)
  rescue JSON::ParserError, TypeError
    raise ArgumentError, "Invalid activity cursor"
  end

  def detail(id)
    event = supported_events.find(id)
    item = project(supported_events.where(id: event.id)).first
    records = event.raw_audit_records.to_a
    item.merge(actor: actor(records), evidence: {
      completion_reason: event.completion_reason, digest: event.evidence_digest,
      records: records.map { |record| record.attributes.slice("position", "record_type", "type_name", "audit_timestamp", "sequence", "payload") }
    }, window_occurrences: window_occurrences(event, item))
  end

  private

  def supported_events
    @host.raw_events.where(category: "selinux_administrative")
      .where("transition_type IN (?) OR boolean_changes <> '[]'::jsonb OR EXISTS (SELECT 1 FROM raw_audit_records WHERE raw_event_id = raw_events.id AND record_type IN (1403, 1404))", RawEvent::STATE_TRANSITIONS)
  end

  def response(items, cursor = nil, **pagination)
    { items: items, coverage: COVERAGE, meta: { page_size: PAGE_SIZE, next_cursor: cursor, total: pagination.fetch(:total) { supported_events.count } }.merge(pagination) }
  end

  def project(relation)
    # Observations coalesce identical heartbeats. Only endpoints and accepted
    # event references retain exact checkpoint times; never interpolate a range.
    sql = <<~SQL
      WITH checkpoints AS (
        SELECT o.host_snapshot_id, s.details->>'boot_id' AS boot_id, o.first_observed_at AS observed_at
        FROM host_snapshot_observations o JOIN host_snapshots s ON s.id = o.host_snapshot_id WHERE o.host_id = :host
        UNION
        SELECT o.host_snapshot_id, s.details->>'boot_id', o.last_observed_at
        FROM host_snapshot_observations o JOIN host_snapshots s ON s.id = o.host_snapshot_id WHERE o.host_id = :host
        UNION
        SELECT host_snapshot_id, boot_id, host_observed_at FROM raw_events
        WHERE host_id = :host AND host_snapshot_id IS NOT NULL AND host_observed_at IS NOT NULL
          AND (category = 'selinux_administrative' OR host_observed_at < audit_timestamp)
      )
      SELECT e.*, previous.host_snapshot_id AS previous_snapshot_id, previous.observed_at AS previous_time,
        refreshed.host_snapshot_id AS refreshed_snapshot_id, refreshed.observed_at AS refreshed_time,
        following.id AS following_id, following.audit_timestamp AS following_time, following.audit_sequence AS following_sequence,
        uncertainty.count AS window_count
      FROM (#{relation.to_sql}) e
      LEFT JOIN LATERAL (SELECT * FROM checkpoints c WHERE c.boot_id = e.boot_id AND c.observed_at < e.audit_timestamp
        ORDER BY c.observed_at DESC, c.host_snapshot_id DESC LIMIT 1) previous ON true
      LEFT JOIN LATERAL (SELECT * FROM checkpoints c WHERE c.boot_id = e.boot_id AND c.observed_at > e.audit_timestamp
        ORDER BY c.observed_at, c.host_snapshot_id LIMIT 1) refreshed ON true
      LEFT JOIN LATERAL (SELECT id, audit_timestamp, audit_sequence FROM raw_events r
        WHERE r.host_id = e.host_id AND r.boot_id = e.boot_id
          AND ((e.transition_type = 'enforcement_change' AND r.transition_type = 'enforcement_change')
            OR (e.transition_type IN ('policy_load', 'boolean_change') AND r.transition_type IN ('policy_load', 'boolean_change')))
          AND (r.audit_timestamp, r.audit_sequence) > (e.audit_timestamp, e.audit_sequence)
        ORDER BY r.audit_timestamp, r.audit_sequence LIMIT 1) following ON true
      LEFT JOIN LATERAL (SELECT count(*) FROM occurrences o JOIN raw_events r ON r.id = o.raw_event_id
        WHERE e.transition_type IS NOT NULL AND o.host_id = e.host_id
          AND ((e.transition_type = 'enforcement_change' AND (o.host_snapshot_id IS NULL OR r.checkpoint_invalidated_fields ? 'enforcement'))
            OR (e.transition_type IN ('policy_load', 'boolean_change') AND o.host_snapshot_id IS NULL))
          AND r.boot_id = e.boot_id AND r.category = 'avc'
          AND (r.audit_timestamp, r.audit_sequence) >= (e.audit_timestamp, e.audit_sequence)
          AND (following.id IS NULL OR (r.audit_timestamp, r.audit_sequence) < (following.audit_timestamp, following.audit_sequence))
          AND (refreshed.observed_at IS NULL OR r.audit_timestamp <= refreshed.observed_at)) uncertainty ON true
      ORDER BY e.audit_timestamp DESC, e.boot_id DESC, e.audit_sequence DESC
    SQL
    events = RawEvent.find_by_sql([sql, { host: @host.id }])
    events.each do |event|
      %w[previous_time refreshed_time following_time].each do |field|
        event[field] = Time.zone.parse(event[field]) if event[field].is_a?(String)
      end
    end
    snapshots = @host.host_snapshots.where(id: events.flat_map { |event| [event.previous_snapshot_id, event.refreshed_snapshot_id] }.compact).index_by(&:id)
    # Actor summaries are needed on initial render; batch retained records for the bounded page.
    ActiveRecord::Associations::Preloader.new(records: events, associations: :raw_audit_records).call
    events.map { |event| item(event, snapshots).merge(actor: actor(event.raw_audit_records)) }
  end

  def item(event, snapshots)
    boundary = RawEvent::STATE_TRANSITIONS.include?(event.transition_type)
    changes = event.boolean_changes.map do |change|
      { name: change["name"], old_value: change["old_value"] == 1, new_value: change["new_value"] == 1,
        state_change_established: change["success"] && change["old_value"] != change["new_value"] }
    end
    enforcement = event.enforcement_changes.map do |change|
      { old_mode: change["old_mode"], new_mode: change["new_mode"],
        state_change_established: change["success"] && change["old_mode"] != change["new_mode"] }
    end
    type = event.transition_type || (event.raw_audit_records.any? { |record| record.record_type == 1404 } ? "enforcement_change" : changes.any? ? "boolean_change" : "policy_load")
    names = changes.map { |change| change[:name] }
    refreshed = checkpoint(event.refreshed_snapshot_id, event.refreshed_time, snapshots, names) if boundary
    status = if !boundary
      "not_applicable"
    elsif event.following_id && (!refreshed || event.following_time <= event.refreshed_time)
      "superseded"
    elsif refreshed
      "reconciled"
    else
      "pending"
    end
    {
      id: event.id, host_id: event.host_id, boot_id: event.boot_id, event_time: event.audit_timestamp.iso8601(6),
      evidence_class: boundary ? "observed_transition" : "administrative_history", transition_type: type,
      boundary_established: boundary, audit_sequence: event.audit_sequence, boolean_changes: changes,
      enforcement_changes: enforcement,
      previous_checkpoint: checkpoint(event.previous_snapshot_id, event.previous_time, snapshots, names),
      reconciliation: { status: status, checkpoint: refreshed,
        next_transition: event.following_id ? { id: event.following_id, event_time: event.following_time.iso8601(6), audit_sequence: event.following_sequence } : nil },
      window_avc_count: event.window_count.to_i
    }
  end

  def checkpoint(id, time, snapshots, names)
    snapshot = snapshots[id]
    return unless snapshot

    selinux = snapshot.details.fetch("selinux", {})
    identity = selinux["policy_identity"] if selinux["policy_identity"].to_s.match?(PolicyArtifact::IDENTITY_FORMAT)
    { id: snapshot.id, host_id: @host.id, boot_id: snapshot.details["boot_id"], event_time: time.iso8601(6),
      evidence_class: "observed_checkpoint", policy_identity: identity, enforcement: selinux["enforcement"],
      booleans: names.uniq.map do |name|
        boolean = Array(selinux["booleans"]).find { |entry| entry["name"] == name }
        value = boolean && boolean["status"] == "observed" && [true, false].include?(boolean["current"]) ? boolean["current"] : nil
        { name: name, value: value }
      end }
  end

  def window_occurrences(event, item)
    return [] unless item[:boundary_established]

    relation = @host.occurrences.joins(:raw_event)
      .where(raw_events: { boot_id: event.boot_id, category: "avc" })
      .where("(raw_events.audit_timestamp, raw_events.audit_sequence) >= (?, ?)", event.audit_timestamp, event.audit_sequence)
    relation = if event.transition_type == "enforcement_change"
      relation.where("occurrences.host_snapshot_id IS NULL OR raw_events.checkpoint_invalidated_fields ? 'enforcement'")
    else
      relation.where(host_snapshot_id: nil)
    end
    following = item.dig(:reconciliation, :next_transition)
    relation = relation.where("(raw_events.audit_timestamp, raw_events.audit_sequence) < (?, ?)", following[:event_time], following[:audit_sequence]) if following
    time = item.dig(:reconciliation, :checkpoint, :event_time)
    relation = relation.where("raw_events.audit_timestamp <= ?", time) if time
    relation.order("raw_events.audit_timestamp DESC, raw_events.audit_sequence DESC, occurrences.id DESC").limit(PAGE_SIZE)
      .pluck("occurrences.id", "occurrences.issue_id", "occurrences.occurred_at").map do |id, issue, occurred_at|
        { id: id, issue_id: issue, event_time: occurred_at }
      end
  end

  def actor(records)
    fields = Hash.new { |hash, key| hash[key] = [] }
    records.select { |record| [1403, 1404, 1405, 1300, 1327].include?(record.record_type) }.each do |record|
        record.payload.scan(/(?:\A|\s)(auid|uid|pid|ses|subj|exe|comm|proctitle)=("(?:\\.|[^"])*"|\S+)/).each do |key, value|
        decoded = if value.start_with?('"')
          value[1...-1].gsub('\\"', '"').gsub('\\\\', '\\')
        elsif %w[exe comm proctitle].include?(key) && value.match?(/\A(?:[0-9A-Fa-f]{2})+\z/)
          [value].pack("H*").force_encoding("UTF-8").scrub.tr("\0", " ")
        else
          value
        end
        fields[key] << decoded
      end
    end
    values = fields.transform_values { |items| items.uniq.one? ? items.first : nil }
    { login_uid: audit_id(values["auid"]), execution_uid: audit_id(values["uid"]), pid: audit_id(values["pid"]), context: values["subj"], session: audit_id(values["ses"]),
      executable: values["exe"], command: values["comm"], proctitle: values["proctitle"] }
  end

  def audit_id(value)
    value.to_i if value.to_s.match?(/\A\d+\z/) && value != "4294967295"
  end
end
