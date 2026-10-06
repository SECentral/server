class ConfigurationQuery
  FAMILIES = %w[overview booleans ports file_contexts modules].freeze
  POLICY_IDENTITY_FORMAT = /\Asha256:[0-9a-f]{64}\z/

  def self.call(family:, policy_identity: nil)
    new(family, policy_identity).call
  end

  def initialize(family, requested_identity)
    @family = family
    @requested_identity = requested_identity
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
      payload[:rows] = rows
      payload[:observed_host_count] = rows.flat_map { |row| row[:host_ids] }.uniq.size
    end
    payload
  end

  def policy_cohorts
    @policy_cohorts ||= @hosts.filter_map do |host|
      observation = host.current_state_observation
      host.policy_identity_for(observation) if observation && !observation.stale?
    end.uniq.sort
  end

  private

  def select_identity
    @requested_identity || policy_cohorts.find { |identity| yield identity } || policy_cohorts.first
  end

  def booleans_family
    identity = select_identity { |candidate| BooleanCatalog.for(candidate) }
    overlay = identity ? BooleanCatalogOverlay.call(hosts: @hosts, policy_identity: identity) : nil
    {
      coverage: @hosts.map { |host| boolean_configuration_state(host) }.tally.merge(observed: 0, unavailable: 0, stale: 0, unknown: 0) { |_key, counted, _zero| counted },
      inventory: boolean_inventory,
      policy_cohorts: policy_cohorts,
      selected_policy_identity: identity,
      catalog: overlay && overlay.dig(:catalog),
      catalog_overlay: overlay
    }
  end

  def ports_family
    identity = select_identity { |candidate| PortCatalog.for(candidate) }
    overlay = identity ? PortCatalogOverlay.call(hosts: @hosts, policy_identity: identity) : nil
    {
      coverage: @hosts.map { |host| port_inventory_state(host) }.tally.merge(observed: 0, partial: 0, unavailable: 0, unknown: 0, stale: 0, no_heartbeat: 0) { |_key, counted, _zero| counted },
      policy_cohorts: policy_cohorts,
      selected_policy_identity: identity,
      catalog: overlay && overlay.dig(:catalog),
      catalog_overlay: overlay
    }
  end

  def configuration_rows
    grouped = {}
    @hosts.each do |host|
      observation = host.current_state_observation
      selinux = observation&.host_snapshot&.details&.dig("selinux") || {}
      inventory = host.port_inventory_for(observation)
      values = case @family
      when "ports" then inventory&.fetch("mappings", [])
      when "file_contexts" then selinux.dig("policy", "file_contexts")
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
    observation = host.current_state_observation
    return :unknown unless observation
    return :stale if observation.stale?

    selinux = observation.host_snapshot.details.fetch("selinux", {})
    return :unavailable if selinux["boolean_status"] == "unavailable"
    return :observed if Array(selinux["booleans"]).any? { |boolean| boolean["status"] == "observed" && boolean["current"].in?([true, false]) }
    return :unavailable if Array(selinux["booleans"]).any? { |boolean| boolean["status"] == "unavailable" }

    :unknown
  end

  def port_inventory_state(host)
    observation = host.current_state_observation
    return :no_heartbeat unless observation
    return :stale if observation.stale?

    status = host.port_inventory_for(observation)["status"]
    %w[observed partial unavailable unknown].include?(status) ? status.to_sym : :unknown
  end

  def boolean_inventory
    names = @hosts.flat_map { |host| Array(host.current_snapshot&.details&.dig("selinux", "booleans")).filter_map { |boolean| boolean["name"] } }.uniq.sort
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
        selinux = observation.host_snapshot.details.fetch("selinux", {})
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
end
