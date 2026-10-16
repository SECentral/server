class HostConfigurationQuery
  VIEWS = %w[differences booleans ports effective_permissive_domains].freeze
  DEVIATION_RESULTS = %w[differs not_observed host_only reference_only].freeze
  class InvalidResults < ArgumentError; end

  def self.call(host, view: "differences", q: nil, page: 1, reference_revision_id: nil, limit: nil, results: nil)
    new(host, view: view, q: q, page: page, reference_revision_id: reference_revision_id, limit: limit, results: results).call
  end

  def initialize(host, view:, q: nil, page: 1, reference_revision_id: nil, limit: nil, results: nil)
    @results = results.nil? ? DEVIATION_RESULTS : results.to_s.split(",").uniq
    raise InvalidResults, "Unknown deviation category" if (@results - DEVIATION_RESULTS).any?

    @page_size = PageSize.parse(limit)
    @host = host
    @comparison = HostConfigurationComparison.call(host, reference_revision_id: reference_revision_id)
    @view = VIEWS.include?(view) ? view : "differences"
    @query = q.to_s.strip.downcase
    @page = [page.to_i, 1].max
  end

  def call
    @deviation_entries = difference_entries
    payload = {
      host: { id: @host.id, hostname: @host.hostname, external_id: @host.external_id },
      observation: observation_payload,
      selinux: selinux_payload,
      reference: reference_payload,
      selection: @comparison.selection.as_json,
      reference_options: CatalogReferenceSelection.options(snapshot: @comparison.snapshot, selinux: @comparison.selinux),
      comparison: comparison_payload,
      view: @view
    }
    payload[:differences] = differences_payload if @view == "differences" && @comparison.comparison_available?
    payload[:booleans] = boolean_page if @view == "booleans"
    payload[:ports] = port_page if @view == "ports"
    payload[:entries] = comparison_page if %w[differences effective_permissive_domains].include?(@view)
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
      policy_identity: @comparison.policy_identity,
      effective_permissive_domains: @comparison.host_permissive_state
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
          content_digest: revision.content_digest,
          lifecycle: revision.catalog_management.lifecycle,
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
      effective_permissive_domains: @comparison.effective_permissive_domains,
      deviations: deviation_summary,
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

  def comparison_page
    rows = @view == "differences" ? @deviation_entries.select { |row| @results.include?(row[:result]) } : domain_entries
    rows = rows.select { |row| [row[:name], row[:host_value], row[:reference_value], row[:description]].join(" ").downcase.include?(@query) } unless @query.empty?
    page = page_window(rows)
    { rows: page[:current], total: page[:total], page: page[:page], page_size: @page_size, pages: page[:pages] }
  end

  def deviation_summary
    return nil unless @comparison.comparison_available? && !@comparison.stale

    {
      total: @deviation_entries.size,
      by_result: DEVIATION_RESULTS.index_with { |result| @deviation_entries.count { |row| row[:result] == result } },
      by_family: %w[boolean port domain].index_with { |kind| @deviation_entries.count { |row| row[:kind] == kind } }
    }
  end

  def difference_entries
    return [] unless @comparison.comparison_available? && !@comparison.stale

    findings = differences_payload
    booleans = findings[:booleans].sort_by { |row| row[:name] }.map do |row|
      { kind: "boolean", name: row[:name], host_value: boolean_text(row[:observed_current]), reference_value: boolean_text(row[:reference_default]), result: row[:kind].to_s, description: row[:description] }
    end
    port_findings = @comparison.selection.family("ports")[:comparison_allowed] ? findings[:ports] : []
    ports = port_findings.map do |row|
      ports = row[:start] == row[:end] ? row[:start].to_s : "#{row[:start]}-#{row[:end]}"
      result = if Array(row[:observed_types]).empty?
        "not_observed"
      elsif Array(row[:catalog_types]).empty?
        "host_only"
      else
        "differs"
      end
      { kind: "port", name: "#{row[:protocol]}/#{ports}", host_value: row[:observed_types].presence&.join(", "), reference_value: row[:catalog_types].presence&.join(", "), result: result, description: row[:local_classification] == "custom" ? "Custom mapping" : nil }
    end
    not_observed = Array(@comparison.boolean_reference_only_rows).sort_by { |row| row[:name] }.map do |row|
      { kind: "boolean", name: row[:name], host_value: nil, reference_value: boolean_text(row[:catalog]["default"]), result: "not_observed", description: row[:catalog]["description"] }
    end
    rows = booleans + ports + domain_entries.select { |row| %w[host_only reference_only].include?(row[:result]) } + not_observed
    rows.sort_by { |row| [row[:result] == "not_observed" ? 1 : 0, row[:kind], row[:name]] }
  end

  def boolean_text(value)
    return nil unless value.in?([true, false])

    value ? "On" : "Off"
  end

  def domain_entries
    comparison = @comparison.effective_permissive_domains
    if comparison[:status] == "observed" && !@comparison.stale
      { "host_only" => comparison[:unexpected_on_host], "reference_only" => comparison[:missing_from_host], "match" => comparison[:matching] }.flat_map do |result, domains|
        Array(domains).sort.map do |name|
          { kind: "domain", name: name, host_value: result == "reference_only" ? "Not in set" : "Permissive", reference_value: result == "host_only" ? "Not in set" : "Permissive", result: result, description: nil }
        end
      end
    elsif @comparison.host_permissive_state[:status] == "observed"
      Array(@comparison.host_permissive_state[:domains]).sort.map do |name|
        { kind: "domain", name: name, host_value: "Permissive", reference_value: nil, result: @comparison.stale ? "stale" : "not_compared", description: nil }
      end
    else
      []
    end
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
    { rows: page[:current], total: page[:total], page: page[:page], page_size: @page_size, pages: page[:pages] }
  end

  def flat_boolean_row(row)
    entry = observed_boolean(row[:name])
    current = nil
    if @comparison.stale
      status = "stale"
    elsif @comparison.selinux["boolean_status"] == "unavailable"
      status = "unavailable"
    elsif !@comparison.selinux["boolean_status"].nil? && !%w[observed partial].include?(@comparison.selinux["boolean_status"])
      status = "unknown"
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
    elsif !@comparison.selinux["boolean_status"].nil? && !%w[observed partial].include?(@comparison.selinux["boolean_status"])
      status = "unknown"
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
    { segments: page[:current], total: page[:total], page: page[:page], page_size: @page_size, pages: page[:pages] }
  end

  def page_window(items)
    total = items.size
    pages = (total / @page_size.to_f).ceil
    page = @page.clamp(1, [pages, 1].max)
    { current: items.slice((page - 1) * @page_size, @page_size) || [], total: total, page: page, pages: pages }
  end
end
