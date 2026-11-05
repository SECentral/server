module McpInvestigation
  class Reader
    class Failure < StandardError
      attr_reader :code

      def initialize(code)
        @code = code
        super(code)
      end
    end

    ISSUE_FIELDS = %i[id source_type target_type target_class permissions status disposition first_seen_at last_seen_at updated_at].freeze
    HOST_FIELDS = %i[id hostname last_seen_at updated_at].freeze
    TEXT_FIELDS = %i[source_type target_type target_class hostname disposition candidate_id candidate_kind evidence_version status action].freeze
    JSON_FIELDS = %i[permissions].freeze
    ID_FIELDS = %i[id host_id issue_signature_id normalized_denial_id raw_event_id host_snapshot_id].freeze

    def initialize(tool, arguments, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
      @tool = tool
      @arguments = arguments.stringify_keys
      @clock = clock
      @deadline = @clock.call + 3
      @omissions = []
      @stored_bytes = 0
    end

    def call
      # A standalone transaction is required: never change an existing caller's
      # transaction or leave a statement timeout on a pooled connection.
      ActiveRecord::Base.connection_pool.with_connection do |connection|
        check_deadline!
        raise Failure, "internal_error" if connection.transaction_open?

        connection.transaction(isolation: :repeatable_read) do
          connection.execute("SET TRANSACTION READ ONLY")
          connection.execute("SET LOCAL statement_timeout = '1000ms'")
          @organization_id = Organization.order(:id).limit(2).pluck(:id).then do |ids|
            raise Failure, "organization_invariant_missing" unless ids.one?

            ids.first
          end
          @issue_id = valid_id(@arguments["issue_id"]) if @arguments.key?("issue_id")
          @host_id = valid_id(@arguments["host_id"]) if @arguments.key?("host_id")
          check_deadline!
          result = dispatch
          check_deadline!
          result
        end
      end
    rescue ActiveRecord::QueryCanceled
      raise Failure, "deadline_exceeded"
    end

    private

    def dispatch
      data = case @tool
      when "get_overview"
        issues = Issue.where(organization_id: @organization_id).group(:status, :disposition).limit(31).count
        raise Failure, "scope_exceeds_limit" if issues.size > 30

        { host_count: Host.where(organization_id: @organization_id).count,
          issues: issues.sort.map { |(status, disposition), count| { status: status, disposition: disposition, count: count } } }
      when "list_issues"
        scope = Issue.where(organization_id: @organization_id)
        status = @arguments.fetch("status", "open")
        scope = scope.where(status: status) unless status == "all"
        %w[source_type target_type target_class].each { |key| scope = scope.where(key => @arguments[key]) if @arguments[key] }
        { issues: page(scope, ISSUE_FIELDS) }
      when "get_issue"
        issue = parent_issue
        signatures = Issue.where(organization_id: @organization_id).select(:id).find(@issue_id).active_signatures
        { issue: issue, active_occurrence_count: Occurrence.where(organization_id: @organization_id, issue_id: @issue_id).count,
          signatures: page(signatures, %i[id permissions status disposition updated_at]) }
      when "list_issue_occurrences"
        parent_issue
        { occurrences: page(Occurrence.where(organization_id: @organization_id, issue_id: @issue_id),
          %i[id host_id issue_signature_id normalized_denial_id raw_event_id host_snapshot_id occurred_at]) }
      when "get_issue_resolution_intent"
        parent_issue
        # Both collections share the page size, but the continuation traverses
        # history only. Refuse an oversized intent scope rather than truncate it.
        intents = project(ResolutionIntent.where(issue_id: @issue_id).order(id: :desc).limit(51),
          %i[id issue_signature_id candidate_id candidate_kind status selected_at evidence_version])
        raise Failure, "scope_exceeds_limit" if intents.size > 50

        { intents: intents, history: page(ResolutionIntentChange.where(issue_id: @issue_id), %i[id issue_signature_id action created_at]) }
      when "list_hosts"
        { hosts: page(Host.where(organization_id: @organization_id), HOST_FIELDS) }
      when "get_host"
        host = project(Host.where(organization_id: @organization_id, id: @host_id), HOST_FIELDS).first
        raise Failure, "not_found" unless host

        { host: host }
      else
        raise Failure, "invalid_arguments"
      end
      {
        scope: { organization_id: @organization_id.to_s, issue_id: @issue_id&.to_s, host_id: @host_id&.to_s,
          selection: @tool == "get_overview" ? "retained_counts" : @arguments.key?("cursor") || @page ? "page" : "requested_record" },
        availability: "available", freshness: "unknown", coverage: @omissions.empty? ? "complete" : "partial",
        reasons: ["no_cross_call_snapshot", "retained_metadata_only", "late_commits_and_filter_updates_may_be_omitted"] + (@omissions.empty? ? [] : ["record_exceeds_budget"]),
        data: data, omitted_fields: @omissions,
        retrieval: { has_more: !!@next_cursor, next_cursor: @next_cursor, change_detection: @changed ? "changed" : "unknown", parent_version: @parent_version }
      }
    end

    def parent_issue
      @parent_issue ||= project(Issue.where(organization_id: @organization_id, id: @issue_id), ISSUE_FIELDS).first.tap do |issue|
        raise Failure, "not_found" unless issue

        @parent_version = issue.fetch(:updated_at)
      end
    end

    def valid_id(value)
      raise Failure, "invalid_arguments" unless value.is_a?(String) && value.match?(/\A[1-9]\d{0,18}\z/) && value.to_i <= 9_223_372_036_854_775_807

      value.to_i
    end

    def page(scope, fields)
      @page = true
      limit = @arguments.fetch("limit", 25)
      filters = @arguments.except("cursor", "limit")
      if @arguments["cursor"]
        cursor = verifier.verified(@arguments["cursor"], purpose: "mcp-page")
        unless cursor.is_a?(Hash) && cursor["tool"] == @tool && cursor["organization_id"] == @organization_id.to_s && cursor["filters"] == filters
          raise Failure, "invalid_arguments"
        end
        upper, before = cursor.values_at("upper", "before")
        raise Failure, "invalid_arguments" unless upper.is_a?(Integer) && before.is_a?(Integer) && before.positive? && upper >= before

        @changed = cursor["parent_version"] != @parent_version
      else
        check_deadline!
        upper = scope.maximum(:id) || 0
        before = upper + 1
      end
      id_column = scope.klass.arel_table[:id]
      selected = scope.where(id_column.lteq(upper).and(id_column.lt(before))).order(id: :desc).limit(limit + 1)
      check_deadline!
      ids = selected.pluck(:id)
      more = ids.size > limit
      rows = project(scope.where(id: ids.first(limit)).order(id: :desc), fields)
      @next_cursor = if more
        verifier.generate({ tool: @tool, organization_id: @organization_id.to_s, filters: filters, upper: upper,
          before: rows.last.fetch(:id).to_i, parent_version: @parent_version }, purpose: "mcp-page", expires_in: 15.minutes)
      end
      rows
    end

    def project(scope, fields)
      check_deadline!
      guarded = fields & (TEXT_FIELDS + JSON_FIELDS)
      allowed = guarded.to_h { |field| [field, projectable(scope, field)] }
      sizes = guarded.map do |field|
        length = byte_length(scope, field)
        Arel::Nodes::Case.new.when(allowed.fetch(field)).then(length).else(0)
      end
      # Scalar IDs/timestamps have fixed upper bounds; reserve 64 bytes each.
      size_expression = sizes.reduce(Arel::Nodes.build_quoted((fields.size - guarded.size) * 64)) { |sum, size| Arel::Nodes::Addition.new(sum, size) }
      @stored_bytes += scope.pluck(size_expression).sum
      raise Failure, "scope_exceeds_limit" if @stored_bytes > 64 * 1024
      check_deadline!

      projection = fields.map do |field|
        column = scope.klass.arel_table[field]
        guarded.include?(field) ? Arel::Nodes::Case.new.when(allowed.fetch(field)).then(column).else(nil) : field
      end
      projection += guarded.map do |field|
        allowed.fetch(field).not
      end
      scope.pluck(*projection).map do |values|
        row = fields.zip(values.first(fields.size)).to_h
        fields.each do |field|
          value = row[field]
          row[field] = if ID_FIELDS.include?(field)
            value&.to_s
          elsif value.respond_to?(:iso8601)
            value.iso8601(6)
          else
            value
          end
        end
        guarded.zip(values.drop(fields.size)).each do |field, oversized|
          @omissions << { record_id: row.fetch(:id), field: field.to_s, reason: "record_exceeds_budget" } if oversized
        end
        row
      end
    end

    def projectable(scope, field)
      return byte_length(scope, field).lteq(512) unless JSON_FIELDS.include?(field)

      column = "#{scope.klass.quoted_table_name}.#{ActiveRecord::Base.connection.quote_column_name(field)}"
      permissions = Contracts::PERMISSIONS
      valid_items = Arel.sql(<<~SQL.squish)
        jsonb_array_length(#{column}) <= #{permissions.fetch(:maxItems)} AND NOT EXISTS (
          SELECT 1 FROM jsonb_array_elements(#{column}) AS permission(value)
          WHERE jsonb_typeof(permission.value) <> 'string'
            OR char_length(permission.value #>> '{}') > #{permissions.fetch(:items).fetch(:maxLength)}
        )
      SQL
      Arel::Nodes::Case.new.when(byte_length(scope, field).lteq(4096)).then(valid_items).else(false)
    end

    def byte_length(scope, field)
      column = scope.klass.arel_table[field]
      cast = Arel::Nodes::NamedFunction.new("CAST", [column.as("text")])
      Arel::Nodes::NamedFunction.new("octet_length", [cast])
    end

    def check_deadline!
      raise Failure, "deadline_exceeded" if @clock.call >= @deadline
    end

    def verifier
      @verifier ||= ActiveSupport::MessageVerifier.new(Rails.application.key_generator.generate_key("mcp-pages-v1", 32), serializer: JSON, url_safe: true)
    end
  end
end
