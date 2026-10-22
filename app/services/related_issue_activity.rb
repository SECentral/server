class RelatedIssueActivity
  WINDOW = 2.seconds
  SAMPLE_LIMIT = 50
  NEIGHBOR_LIMIT = 200

  def self.call(issue)
    new(issue).call
  end

  def initialize(issue)
    @issue = issue
  end

  def call
    anchors = @issue.occurrences.where(organization_id: @issue.organization_id).includes(:host, raw_event: :raw_audit_records).order(occurred_at: :desc, id: :desc).limit(SAMPLE_LIMIT).to_a
    # ponytail: bounded recent activity, not an incident index or a complete process lifetime.
    matches = anchors.group_by { |o| [o.host_id, o.raw_event.boot_id] }.flat_map do |(host_id, boot_id), items|
      next [] if boot_id.blank?

      neighbors = Occurrence.where(organization_id: @issue.organization_id, host_id: host_id).where.not(issue_id: [nil, @issue.id])
        .joins(:issue, :raw_event).where(issues: { organization_id: @issue.organization_id },
          raw_events: { organization_id: @issue.organization_id, host_id: host_id, boot_id: boot_id })
        .where(occurred_at: (items.map(&:occurred_at).min - WINDOW)..(items.map(&:occurred_at).max + WINDOW))
        .includes(:issue, :host, raw_event: :raw_audit_records).order(occurred_at: :desc, id: :desc).limit(NEIGHBOR_LIMIT)
      neighbors.filter_map do |other|
        same_event = items.find { |o| o.raw_event_id == other.raw_event_id }
        anchor = same_event || items.find do |o|
          next false unless (o.occurred_at - other.occurred_at).abs <= WINDOW

          identity(o).present? && identity(o) == identity(other)
        end
        next unless anchor

        { issue_id: other.issue_id, target_type: other.issue.target_type, target_class: other.issue.target_class,
          host_id: host_id, hostname: other.host.hostname, occurrence_id: other.id, source_occurrence_id: anchor.id,
          occurred_at: other.occurred_at, source_occurred_at: anchor.occurred_at,
          basis: same_event ? "same_audit_event" : "same_process_window" }
      end
    end
    matches.uniq { |m| [m[:issue_id], m[:host_id]] }.first(10)
  end

  private

  def identity(occurrence)
    @identities ||= {}
    @identities.fetch(occurrence.raw_event_id) do
      @identities[occurrence.raw_event_id] = AvcNormalizer.new(occurrence.raw_event.raw_audit_records.to_a).process_identity
    end
  end
end
