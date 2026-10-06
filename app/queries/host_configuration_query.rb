class HostConfigurationQuery
  PAGE_SIZE = 50
  VIEWS = %w[differences booleans ports].freeze

  def self.call(host, view: "differences", q: nil, page: 1)
    new(host, view: view, q: q, page: page).call
  end

  def initialize(host, view:, q: nil, page: 1)
    @host = host
    @comparison = HostConfigurationComparison.call(host)
    @view = VIEWS.include?(view) ? view : "differences"
    @query = q.to_s.strip.downcase
    @page = [page.to_i, 1].max
  end

  def call
    payload = {
      host: { id: @host.id, hostname: @host.hostname, external_id: @host.external_id },
      observation: observation_payload,
      selinux: selinux_payload,
      reference: reference_payload,
      comparison: comparison_payload,
      view: @view
    }
    payload[:differences] = differences_payload if @view == "differences" && @comparison.comparison_available?
    payload[:booleans] = boolean_page if @view == "booleans"
    payload[:ports] = port_page if @view == "ports"
    payload
  end

  private

  def observation_payload
    observation = @comparison.observation
    return nil unless observation

    {
      status: observation.stale? ? "stale" : "current",
      last_observed_at: observation.last_observed_at,
      last_received_at: observation.last_received_at
    }
  end

  def selinux_payload
    selinux = @comparison.selinux
    {
      enforcement: selinux["enforcement"],
      configured_policy_type: selinux["configured_policy_type"],
      boolean_status: selinux["boolean_status"],
      port_inventory_status: selinux.dig("policy", "port_inventory", "status"),
      file_context_mappings_status: selinux.dig("policy", "file_context_mappings_status") || "unknown",
      policy_identity: @comparison.policy_identity
    }
  end

  def reference_payload
    reference = @comparison.reference
    if reference
      revision = reference.revision
      {
        kind: "distribution_catalog",
        catalog_revision: {
          id: revision.id,
          display_name: revision.display_name,
          policy_type: revision.policy_type,
          architecture: revision.architecture,
          loaded_policy_digest: revision.loaded_policy_digest,
          applicability: reference.applicability
        }
      }
    else
      { kind: "none" }
    end
  end

  def comparison_payload
    {
      available: !!@comparison.comparison_available?,
      paused: @comparison.stale,
      summary: {
        booleans: boolean_summary_payload,
        ports: port_summary_payload
      }
    }
  end

  def boolean_summary_payload
    summary = @comparison.boolean_summary
    return nil unless summary

    {
      reference_entries: @comparison.boolean_reference_entries,
      compared: summary[:match] + summary[:differ],
      match: summary[:match],
      differ: summary[:differ],
      host_only: summary[:host_only],
      not_observed: @comparison.boolean_reference_only_rows.size,
      unavailable: @comparison.boolean_unavailable_rows.size
    }
  end

  def port_summary_payload
    summary = @comparison.port_summary
    return nil unless summary

    {
      compared: summary[:match] + summary[:differ],
      match: summary[:match],
      differ: summary[:differ],
      not_observed: summary[:not_observed]
    }
  end

  def differences_payload
    differences = Array(@comparison.boolean_differences)
    boolean_findings = differences.map { |row| boolean_finding(row, :differs) }
    boolean_findings += Array(@comparison.boolean_host_only_rows).map { |row| boolean_finding(row, :host_only) }
    port_findings = Array(@comparison.port_difference_segments).map { |segment| segment.except(:host_id, :hostname) }.sort_by { |segment| [segment[:protocol], segment[:start]] }
    {
      total: boolean_findings.size + port_findings.size,
      booleans: boolean_findings,
      ports: port_findings,
      limitations: {
        reference_only_booleans: Array(@comparison.boolean_reference_only_rows).map { |row| row[:name] },
        unavailable_booleans: Array(@comparison.boolean_unavailable_rows).map { |row| row[:name] },
        port_segments: Array(@comparison.port_limitation_segments).map { |segment| segment.except(:host_id, :hostname) }
      }
    }
  end

  def boolean_finding(row, kind)
    observed = observed_boolean(row[:name])
    {
      name: row[:name],
      kind: kind,
      reference_default: row[:catalog]&.fetch("default", nil),
      observed_current: observed && observed["current"].in?([true, false]) ? observed["current"] : nil,
      host_reported_default: observed && (observed.key?("default") ? observed["default"] : observed["persistent"]),
      description: row[:catalog]&.fetch("description", nil)
    }
  end

  def observed_boolean(name)
    Array(@comparison.selinux["booleans"]).find { |entry| entry["name"] == name }
  end

  def boolean_page
    rows = if @comparison.boolean_overlay
      Array(@comparison.boolean_rows).map { |row| flat_boolean_row(row) }
    else
      Array(@comparison.selinux["booleans"]).map { |entry| raw_boolean_row(entry) }
    end
    rows.sort_by! { |row| [boolean_result_priority(row), row[:name]] }
    unless @query.empty?
      rows = rows.select do |row|
        row[:name].to_s.downcase.include?(@query) || row[:description].to_s.downcase.include?(@query)
      end
    end
    page = page_window(rows)
    { rows: page[:current], total: page[:total], page: page[:page], page_size: PAGE_SIZE, pages: page[:pages] }
  end

  def flat_boolean_row(row)
    entry = observed_boolean(row[:name])
    current = nil
    if @comparison.stale
      status = "stale"
    elsif @comparison.selinux["boolean_status"] == "unavailable"
      status = "unavailable"
    elsif entry.nil?
      status = "not_observed"
    elsif entry["status"] == "unavailable"
      status = "unavailable"
    elsif entry["status"] == "observed" && entry["current"].in?([true, false])
      current = entry["current"]
      status = "observed"
    else
      status = "unknown"
    end
    {
      name: row[:name],
      current: current,
      host_default: entry && (entry.key?("default") ? entry["default"] : entry["persistent"]),
      reference_default: row[:catalog]&.fetch("default", nil),
      description: row[:catalog]&.fetch("description", nil),
      catalog_status: row[:catalog_status],
      status: status
    }
  end

  def raw_boolean_row(entry)
    current = nil
    if @comparison.stale
      status = "stale"
    elsif @comparison.selinux["boolean_status"] == "unavailable"
      status = "unavailable"
    elsif entry["status"] == "unavailable"
      status = "unavailable"
    elsif entry["status"] == "observed" && entry["current"].in?([true, false])
      current = entry["current"]
      status = "observed"
    else
      status = "unknown"
    end
    {
      name: entry["name"],
      current: current,
      host_default: entry.key?("default") ? entry["default"] : entry["persistent"],
      reference_default: nil,
      description: nil,
      catalog_status: "unavailable",
      status: status
    }
  end

  def boolean_result_priority(row)
    compared = row[:status] == "observed" && row[:catalog_status] == "defined" && row[:current].in?([true, false]) && row[:reference_default].in?([true, false])
    return row[:current] == row[:reference_default] ? 2 : 0 if compared

    1
  end

  def port_page
    segments = Array(@comparison.port_segments).map { |segment| segment.except(:host_id, :hostname) }.sort_by do |segment|
      priority = case segment[:relation]
      when "matching_effective_type" then 2
      when "comparison_unknown" then 1
      else 0
      end
      [priority, segment[:protocol], segment[:start]]
    end
    unless @query.empty?
      number = @query.match?(/\A\d+\z/) ? @query.to_i : nil
      segments = segments.select do |segment|
        segment[:protocol].to_s.downcase == @query ||
          (number && number >= segment[:start].to_i && number <= segment[:end].to_i) ||
          (Array(segment[:catalog_types]) + Array(segment[:observed_types])).any? { |type| type.to_s.downcase.include?(@query) }
      end
    end
    page = page_window(segments)
    { segments: page[:current], total: page[:total], page: page[:page], page_size: PAGE_SIZE, pages: page[:pages] }
  end

  def page_window(items)
    total = items.size
    pages = (total / PAGE_SIZE.to_f).ceil
    page = @page.clamp(1, [pages, 1].max)
    { current: items.slice((page - 1) * PAGE_SIZE, PAGE_SIZE) || [], total: total, page: page, pages: pages }
  end
end
