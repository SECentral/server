module McpInvestigation
  module Contracts
    ID = { type: "string", pattern: "^[1-9][0-9]{0,18}$", maxLength: 19 }.freeze
    TEXT = { type: ["string", "null"], maxLength: 512 }.freeze
    TIME = { type: ["string", "null"], format: "date-time" }.freeze
    OPTIONAL_ID = { anyOf: [ID, { type: "null" }] }.freeze
    COUNT = { type: "integer", minimum: 0 }.freeze
    PERMISSIONS = { type: ["array", "null"], items: { type: "string", maxLength: 512 }, maxItems: 512 }.freeze
    PAGE_INPUT = { limit: { type: "integer", minimum: 1, maximum: 50 }, cursor: { type: "string", minLength: 1, maxLength: 2048 } }.freeze
    FILTER = { type: "string", pattern: "^[A-Za-z_][A-Za-z0-9_]*$", maxLength: 128 }.freeze

    def self.object(properties = nil, required: nil, **fields)
      properties ||= fields
      required ||= properties.keys
      { type: "object", properties: properties, required: required.map(&:to_s), additionalProperties: false }
    end

    def self.array(schema, max: 50)
      { type: "array", items: schema, maxItems: max }
    end

    def self.input(name)
      properties, required = case name
      when "get_overview" then [{}, []]
      when "list_issues"
        [PAGE_INPUT.merge(status: { enum: Issue::STATUSES + ["all"] }, source_type: FILTER, target_type: FILTER, target_class: FILTER), []]
      when "get_issue", "get_issue_resolution_intent", "list_issue_occurrences"
        [PAGE_INPUT.merge(issue_id: ID), [:issue_id]]
      when "list_hosts" then [PAGE_INPUT, []]
      when "get_host" then [{ host_id: ID }, [:host_id]]
      end
      object(properties, required: required)
    end

    def self.issue
      object(id: ID, source_type: TEXT, target_type: TEXT, target_class: TEXT, permissions: PERMISSIONS,
        status: { enum: Issue::STATUSES }, disposition: TEXT, first_seen_at: TIME, last_seen_at: TIME, updated_at: TIME)
    end

    def self.host
      object(id: ID, hostname: TEXT, last_seen_at: TIME, updated_at: TIME)
    end

    def self.data(name)
      case name
      when "get_overview"
        object(host_count: COUNT, issues: array(object(status: TEXT, disposition: TEXT, count: COUNT), max: 30))
      when "list_issues" then object(issues: array(issue))
      when "get_issue"
        signature = object(id: ID, permissions: PERMISSIONS, status: TEXT, disposition: TEXT, updated_at: TIME)
        object(issue: issue, active_occurrence_count: COUNT, signatures: array(signature))
      when "list_issue_occurrences"
        occurrence = object(id: ID, host_id: ID, issue_signature_id: OPTIONAL_ID, normalized_denial_id: ID,
          raw_event_id: ID, host_snapshot_id: OPTIONAL_ID, occurred_at: TIME)
        object(occurrences: array(occurrence))
      when "get_issue_resolution_intent"
        intent = object(id: ID, issue_signature_id: OPTIONAL_ID, candidate_id: TEXT, candidate_kind: TEXT,
          status: TEXT, selected_at: TIME, evidence_version: TEXT)
        history = object(id: ID, issue_signature_id: OPTIONAL_ID, action: TEXT, created_at: TIME)
        object(intents: array(intent), history: array(history))
      when "list_hosts" then object(hosts: array(host))
      when "get_host" then object(host: host)
      end
    end

    def self.output(name)
      omission = object(record_id: ID, field: { type: "string", maxLength: 64 }, reason: { const: "record_exceeds_budget" })
      success = object(
        scope: object(organization_id: ID, issue_id: OPTIONAL_ID, host_id: OPTIONAL_ID,
          selection: { enum: %w[page requested_record retained_counts] }),
        availability: { const: "available" }, freshness: { const: "unknown" }, coverage: { enum: %w[complete partial] },
        reasons: array({ type: "string", maxLength: 64 }, max: 10),
        data: data(name), omitted_fields: array(omission, max: 1000),
        retrieval: object(has_more: { type: "boolean" }, next_cursor: { type: ["string", "null"], maxLength: 2048 },
          change_detection: { enum: %w[unknown changed] }, parent_version: TIME))
      error = object(error: object(code: { enum: %w[not_found invalid_arguments organization_invariant_missing scope_exceeds_limit record_exceeds_budget deadline_exceeded internal_error] },
        scope: { type: "string", maxLength: 64 }, retry_guidance: { type: "string", maxLength: 256 }))
      { type: "object", oneOf: [success, error] }
    end
  end
end
