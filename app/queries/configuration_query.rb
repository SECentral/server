class ConfigurationQuery
  FAMILIES = %w[overview booleans ports file_contexts modules].freeze
  POLICY_IDENTITY_FORMAT = /\Asha256:[0-9a-f]{64}\z/

  def self.call(family:, policy_identity: nil, page: 1, limit: 25, query: nil, protocol: nil)
    new(family, policy_identity, page, limit, query, protocol).call
  end

  def initialize(family, requested_identity, page, page_size, query, protocol)
    @family = family
    @requested_identity = requested_identity
    @page = page
    @page_size = page_size
    @query = query.to_s.strip.downcase
    @protocol = protocol
    @hosts = Host.includes(:host_snapshots).order(:hostname, :external_id).to_a
  end

  def call
    payload = {
      family: @family,
      families: FAMILIES,
      hosts: { total: @hosts.size }
    }
    case @family
    when "booleans" then payload[:booleans] = booleans_family
    when "ports" then payload[:ports] = ports_family
    when "file_contexts", "modules"
      rows = configuration_rows
      payload[:observed_host_count] = rows.flat_map { |row| row[:host_ids] }.uniq.size
      payload[:rows], payload[:pagination] = paginate(rows)
    end
    payload
  end

  def policy_cohorts
    policy_cohort_details.map { |cohort| cohort[:policy_identity] }
  end

  def policy_cohort_details
    @policy_cohort_details ||= @hosts.filter_map do |host|
      observation = host.current_state_observation
      next unless observation && !observation.stale?

      identity = host.policy_identity_for(observation)
      next unless identity

      details = observation.host_snapshot.details
      platform = details.fetch("platform", {})
      selinux = host.selinux_state_for(observation)
      {
        policy_identity: identity,
        os_id: platform["os_id"],
        os_version: platform["os_version"],
        policy_type: selinux["configured_policy_type"],
        architecture: platform["architecture"],
        last_observed_at: observation.last_observed_at
      }
    end.group_by { |entry| entry[:policy_identity] }.map do |identity, entries|
      platforms = entries.group_by { |entry| entry.values_at(:os_id, :os_version, :policy_type, :architecture) }.map do |(os_id, os_version, policy_type, architecture), hosts|
        { os_id: os_id, os_version: os_version, policy_type: policy_type, architecture: architecture, host_count: hosts.size }
      end
      {
        policy_identity: identity,
        host_count: entries.size,
        latest_observation_at: entries.map { |entry| entry[:last_observed_at] }.compact.max,
        platforms: platforms
      }
    end.sort_by { |cohort| cohort[:policy_identity] }
  end

  private

  def select_identity
    @requested_identity || policy_cohorts.find { |identity| yield identity } || policy_cohorts.first
  end

  def booleans_family
    identity = select_identity { |candidate| BooleanCatalog.for(candidate) }
    overlay = identity ? BooleanCatalogOverlay.call(hosts: @hosts, policy_identity: identity) : nil
    inventory, inventory_page = paginate(boolean_inventory)
    overlay = paginate_overlay(overlay)
    {
      coverage: @hosts.map { |host| boolean_configuration_state(host) }.tally.merge(observed: 0, unavailable: 0, stale: 0, unknown: 0) { |_key, counted, _zero| counted },
      inventory: inventory,
      pagination: overlay ? overlay[:pagination] : inventory_page,
      policy_cohorts: policy_cohorts,
      cohort_details: policy_cohort_details,
      selected_policy_identity: identity,
      selection: CatalogReferenceSelection.for_policy_identity(identity).as_json,
      catalog: overlay && overlay.dig(:catalog),
      catalog_overlay: overlay
    }
  end

  def paginate_overlay(overlay)
    return overlay unless overlay
    observed = overlay.dig(:observed)
    observed[:rows], pagination = paginate(observed[:rows])
    overlay.merge(pagination: pagination)
  end

  def paginate(rows)
    rows = rows.select { |row| search_text(row).include?(@query) } if @query.present?
    total = rows.size
    pages = (total / @page_size.to_f).ceil
    page = pages.zero? ? 1 : [@page, pages].min
    [rows.slice((page - 1) * @page_size, @page_size) || [], { total: total, page: page, page_size: @page_size, total_pages: pages }]
  end

  def ports_family
    identity = select_identity { |candidate| PortCatalog.for(candidate) }
    overlay = identity ? PortCatalogOverlay.call(hosts: @hosts, policy_identity: identity) : nil
    if overlay
      observed = overlay[:observed]
      catalog_available = overlay.dig(:catalog, :available) || overlay.dig(:catalog, "available")
      key = catalog_available ? :segments : :observed_mappings
      rows = observed.fetch(key).select { |row| protocol_matches?(row) }
      observed[key], pagination = paginate(aggregate_port_rows(rows))
      observed[:stale_observed_mappings] = aggregate_port_rows(observed[:stale_observed_mappings]) unless key == :segments
      overlay = overlay.merge(pagination: pagination)
    else
      rows, pagination = paginate(configuration_rows.select { |row| protocol_matches?(row) })
    end
    {
      coverage: @hosts.map { |host| port_inventory_state(host) }.tally.merge(observed: 0, partial: 0, unavailable: 0, unknown: 0, stale: 0, no_heartbeat: 0) { |_key, counted, _zero| counted },
      policy_cohorts: policy_cohorts,
      cohort_details: policy_cohort_details,
      selected_policy_identity: identity,
      selection: CatalogReferenceSelection.for_policy_identity(identity).as_json,
      catalog: overlay && overlay.dig(:catalog),
      catalog_overlay: overlay,
      pagination: overlay ? overlay[:pagination] : pagination
    }.tap { |family| family[:rows] = rows unless overlay }
  end

  def configuration_rows
    grouped = {}
    @hosts.each do |host|
      observation = host.current_state_observation
      selinux = observation&.host_snapshot&.details&.dig("selinux") || {}
      inventory = host.port_inventory_for(observation)
      values = case @family
      when "ports" then inventory&.fetch("mappings", [])
      when "file_contexts" then host.file_context_mappings_for(observation)["mappings"]
      when "modules" then selinux.dig("policy", "modules").presence || selinux.dig("policy", "custom_modules")
      end
      next if values.blank? || observation.nil? || observation.stale?
      next if @family == "ports" && !%w[observed partial].include?(inventory["status"])

      Array(values).each do |value|
        normalized = normalize_configuration_value(value)
        key = normalized.except(:host_ids)
        row = grouped[key] ||= normalized.merge(host_ids: [])
        row[:host_ids] << host.id
      end
    end
    grouped.values.sort_by { |row| row.values_at(:type, :pattern, :name, :protocol, :ports).compact.join(" ") }
  end

  def aggregate_port_rows(rows)
    rows.group_by { |row| row.except(:host_id, :hostname, :host_count) }.map do |attributes, hosts|
      host_ids = hosts.filter_map { |host| host[:host_id] }.uniq
      attributes.merge(host_count: host_ids.empty? ? hosts.size : host_ids.size)
    end
  end

  def protocol_matches?(row)
    @protocol.nil? || row[:protocol] == @protocol
  end

  def search_text(row)
    text = row.values.join(" ").downcase
    return text unless @family == "ports" && row[:protocol]

    ranges = row[:ports].presence || [row]
    ports = ranges.map { |range| "#{row[:protocol]}/#{range[:start]}-#{range[:end]}" }
    "#{text} #{ports.join(' ')}".downcase
  end

  def normalize_configuration_value(value)
    case @family
    when "ports"
      {
        type: value["type"],
        protocol: value["protocol"],
        ports: Array(value["ports"]).map { |range| { start: range["start"], end: range["end"], provenance: range["provenance"] } },
        provenance: Array(value["ports"]).map { |range| range["provenance"] }.compact.uniq
      }
    when "file_contexts"
      { pattern: value["pattern"], file_type: value["file_type"], context: value["context"], provenance: [value["provenance"]].compact }
    else
      {
        name: value["name"],
        priority: value["priority"],
        version: value["version"].presence,
        source_package: value["source_package"].presence,
        provenance: [value["provenance"]].compact
      }
    end
  end

  def boolean_configuration_state(host)
    host.boolean_configuration_state
  end

  def port_inventory_state(host)
    host.port_inventory_state
  end

  def boolean_inventory
    names = @hosts.flat_map { |host| Array(selinux_state(host)["booleans"]).filter_map { |boolean| boolean["name"] } }.uniq.sort
    names.map do |name|
      counts = { enabled: 0, disabled: 0, unknown: 0, unavailable: 0, stale: 0, drift: 0 }
      description = nil
      @hosts.each do |host|
        observation = host.current_state_observation
        if observation.nil?
          counts[:unknown] += 1
          next
        end
        if observation.stale?
          counts[:stale] += 1
          next
        end
        selinux = selinux_state(host)
        if selinux["boolean_status"] == "unavailable"
          counts[:unavailable] += 1
          next
        end
        boolean = Array(selinux["booleans"]).find { |entry| entry["name"] == name }
        if boolean.nil? || !%w[observed unavailable].include?(boolean["status"])
          counts[:unknown] += 1
        elsif boolean["status"] == "unavailable"
          counts[:unavailable] += 1
        elsif !boolean["current"].in?([true, false])
          counts[:unknown] += 1
        elsif boolean["current"]
          counts[:enabled] += 1
        else
          counts[:disabled] += 1
        end
        description ||= boolean["description"] if boolean
        default = boolean && (boolean.key?("default") ? boolean["default"] : boolean["persistent"])
        counts[:drift] += 1 if boolean&.fetch("status", nil) == "observed" && boolean["current"].in?([true, false]) && default.in?([true, false]) && boolean["current"] != default
      end
      { name: name, description: description, counts: counts }
    end
  end

  def selinux_state(host)
    @selinux_states ||= {}
    @selinux_states[host.id] ||= host.selinux_state_for
  end
end
