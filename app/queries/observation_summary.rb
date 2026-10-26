class ObservationSummary
  DETAILS_SQL = Arel.sql(<<~SQL.squish).freeze
    jsonb_build_object(
      'enforcement_mode', normalized_denials.details->'enforcement_mode',
      'permissive', normalized_denials.details->'permissive',
      'syscall_evidence', normalized_denials.details->'syscall_evidence')
  SQL

  def self.call(scope)
    from_rows(scope.joins(:normalized_denial).pluck(:raw_event_id, DETAILS_SQL))
  end

  # Rows are AVC decisions; raw_event_id identifies the enclosing audit event.
  def self.from_rows(rows)
    events = rows.group_by(&:first)
    event_outcomes = events.transform_values do |items|
      NormalizedDenial.syscall_outcome("syscall_evidence" => items.flat_map { |_, details| Array(details["syscall_evidence"]) })
    end
    outcomes = event_outcomes.values.tally
    {
      occurrences: rows.size,
      audit_events: events.size,
      modes: rows.map { |_, details| NormalizedDenial.enforcement(details) }.tally,
      decision_outcomes: rows.map { |id, details| [NormalizedDenial.enforcement(details), event_outcomes.fetch(id)] }.tally.map do |(mode, outcome), count|
        { enforcement_mode: mode, syscall_outcome: outcome, occurrences: count }
      end,
      syscall_outcomes: %w[failed succeeded unknown].index_with { |outcome| outcomes.fetch(outcome, 0) }
    }
  end
end
