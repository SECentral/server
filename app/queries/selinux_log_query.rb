class SelinuxLogQuery
  COVERAGE = "Retained AVC occurrences (including ungrouped occurrences) and supported policy loads, boolean/enforcement activity, and port/file-context mapping writes. Raw AVCs without occurrences are not listed. Absence of an entry does not prove that no operation or change occurred. Timestamps across hosts do not establish causation.".freeze
  TIMESTAMP = /\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\z/

  def self.host_ids(filters)
    raise ArgumentError, "Use host_id or host_ids, not both" if filters.key?("host_id") && filters.key?("host_ids")
    return [] unless filters.key?("host_id") || filters.key?("host_ids")
    ids = filters.key?("host_id") ? [filters["host_id"]] : filters["host_ids"]
    raise ArgumentError, "Expected 1 to 50 host IDs" unless ids.is_a?(Array) && ids.size.between?(1, 50)
    ids.map do |id|
      raise ArgumentError, "Invalid host ID" unless id.is_a?(String) && id.match?(/\A[1-9]\d{0,18}\z/) && id.to_i <= 9_223_372_036_854_775_807
      id.to_i
    end.uniq.sort
  end

  def initialize(organization:, filters: {})
    @organization = organization
    @category = filters.fetch("category", "all")
    raise ArgumentError, "Unknown log category" unless %w[all avc administrative].include?(@category)
    @limit = integer(filters.fetch("limit", "50"), 50)
    @host_ids = self.class.host_ids(filters)
    raise ActiveRecord::RecordNotFound unless @host_ids.empty? || @organization.hosts.where(id: @host_ids).count == @host_ids.size
    @start = timestamp(filters["start"]) if filters.key?("start")
    @end = timestamp(filters["end"]) if filters.key?("end")
    raise ArgumentError, "Start must be before end" if @start && @end && @start >= @end
    host_binding = @host_ids.one? ? @host_ids.first : @host_ids.presence
    @binding = [@organization.id, @category, host_binding, @start&.iso8601(6), @end&.iso8601(6)]
    @page = integer(filters["page"]) if filters.key?("page")
    raise ArgumentError, "Page cannot be combined with before" if @page && filters.key?("before")
    @cursor = decode(filters["before"]) if filters.key?("before")
  end

  def call
    if @page
      total = relations.sum { |relation, table, _kind| filtered(relation, table).count }
      pages = (total / @limit.to_f).ceil
      @page = [@page, [pages, 1].max].min
    end
    rows = ActiveRecord::Base.connection.select_all(sql).to_a
    more = rows.size > @limit
    rows = rows.first(@limit)
    occurrences = @organization.occurrences.where(id: rows.select { |row| row["source_kind"] == 0 }.map { |row| row["source_id"] })
      .includes(:host, :normalized_denial, :issue).index_by(&:id)
    events = @organization.raw_events.where(id: rows.select { |row| row["source_kind"] == 1 }.map { |row| row["source_id"] })
      .includes(:host, :raw_audit_records).index_by(&:id)
    items = rows.filter_map do |row|
      record = row["source_kind"] == 0 ? occurrences[row["source_id"]] : events[row["source_id"]]
      next unless record # A deletion between page selection and loading removes the entry.
      host = record.host
      item = { id: record.id, event_time: row_time(row).iso8601(6), host: { id: host.id, hostname: host.hostname, external_id: host.external_id } }
      if row["source_kind"] == 0
        denial = record.normalized_denial
        issue_id = record.issue_id if record.issue&.organization_id == @organization.id
        item.merge(category: "avc", issue_id: issue_id, avc: denial.attributes.slice("status", "source_type", "target_type", "target_class", "permissions", "target_paths", "command", "executable").merge("permissive" => denial.details["permissive"]))
      else
        item.merge(category: "administrative", administrative: SelinuxAdministrativeEvent.facts(record), actor: SelinuxAdministrativeEvent.actor(record.raw_audit_records))
      end
    end
    cursor = verifier.generate({ "version" => 1, "filters" => @binding, "key" => [row_time(rows.last).iso8601(6), rows.last["source_kind"], rows.last["source_id"]] }) if more && !@page
    meta = { page_size: @limit, next_cursor: cursor }
    meta.merge!(page: @page, total: total, total_pages: pages) if @page
    { items: items, coverage: COVERAGE, meta: meta }
  end

  # Exposed for reproducible EXPLAIN measurements of the actual page query.
  def sql
    branches = relations.map { |relation, table, kind| branch(relation, table, kind) }
    offset = @page ? " OFFSET #{(@page - 1) * @limit}" : ""
    limit = @page ? @limit : @limit + 1
    "SELECT * FROM (#{branches.map { |query| "(#{query})" }.join(' UNION ALL ')}) timeline ORDER BY event_time DESC, source_kind DESC, source_id DESC LIMIT #{limit}#{offset}"
  end

  private

  def relations
    branches = []
    if @category != "administrative"
      relation = @organization.occurrences.joins(:raw_event, :host)
        .where(raw_events: { organization_id: @organization.id, category: "avc" }, hosts: { organization_id: @organization.id })
        .where("raw_events.host_id = occurrences.host_id")
      branches << [relation, "occurrences", 0]
    end
    if @category != "avc"
      relation = SelinuxAdministrativeEvent.supported(@organization.raw_events.joins(:host).where(hosts: { organization_id: @organization.id }))
      branches << [relation, "raw_events", 1]
    end
    branches
  end

  def filtered(relation, table)
    relation = relation.where("#{table}.host_id IN (?) AND raw_events.host_id IN (?)", @host_ids, @host_ids) if @host_ids.any?
    relation = relation.where("raw_events.audit_timestamp >= ?", @start) if @start
    relation = relation.where("raw_events.audit_timestamp < ?", @end) if @end
    relation
  end

  def branch(relation, table, kind)
    relation = filtered(relation, table)
    relation = relation.where("(raw_events.audit_timestamp, #{kind}, #{table}.id) < (?, ?, ?)", *@cursor) if @cursor
    relation.select("raw_events.audit_timestamp AS event_time, #{kind} AS source_kind, #{table}.id AS source_id")
      .order(Arel.sql("raw_events.audit_timestamp DESC, #{table}.id DESC")).limit(@page ? @page * @limit : @limit + 1).to_sql
  end

  def integer(value, max = 9_223_372_036_854_775_807)
    raise ArgumentError, "Invalid positive integer" unless value.is_a?(String) && value.match?(/\A[1-9]\d*\z/) && value.to_i <= max
    value.to_i
  end

  def timestamp(value)
    raise ArgumentError, "Expected a UTC timestamp with at most six fractional digits" unless value.is_a?(String) && value.match?(TIMESTAMP) && !value.start_with?("0000")
    date, clock = value.delete_suffix("Z").split("T")
    raise ArgumentError, "Invalid UTC timestamp" unless Date.iso8601(date) && clock[0, 8].split(":").map(&:to_i).zip([23, 59, 59]).all? { |part, max| part <= max }
    Time.iso8601(value).utc
  rescue Date::Error
    raise ArgumentError, "Invalid UTC timestamp"
  end

  def verifier
    Rails.application.message_verifier("selinux-log-cursor")
  end

  def decode(value)
    raise ArgumentError, "Invalid log cursor" unless value.is_a?(String) && value.bytesize <= 4096
    data = verifier.verified(value)
    raise ArgumentError, "Invalid log cursor or filters changed" unless data.is_a?(Hash) && data["version"] == 1 && data["filters"] == @binding
    key = data["key"]
    raise ArgumentError, "Invalid log cursor" unless key.is_a?(Array) && key.size == 3 && [0, 1].include?(key[1]) && key[2].is_a?(Integer) && key[2].positive?
    [timestamp(key[0]), key[1], key[2]]
  end

  def row_time(row)
    value = row.fetch("event_time")
    value.is_a?(String) ? Time.parse(value).utc : value.utc
  end
end
