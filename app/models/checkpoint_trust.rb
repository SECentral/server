# Immutable observation + known trust boundaries; never a reconstructed state.
class CheckpointTrust
  FIELDS = %w[policy_identity booleans enforcement ports file_context_mappings].freeze
  TRANSITION_FIELDS = {
    "policy_load" => %w[policy_identity booleans ports file_context_mappings].freeze,
    "boolean_change" => %w[policy_identity booleans].freeze,
    "enforcement_change" => %w[enforcement].freeze,
    "port_change" => %w[policy_identity ports].freeze,
    "file_context_change" => %w[file_context_mappings].freeze
  }.freeze
  # Preserve the live-accepted stronger policy/boolean association boundary.
  WITHHELD_ASSOCIATIONS = %w[policy_load boolean_change].freeze

  def self.fields_for(types)
    Array(types).flat_map { |type| TRANSITION_FIELDS.fetch(type, []) }.uniq.sort
  end

  def self.for_host(host, observation)
    return new(nil) unless observation

    evidence = host.raw_events.where(boot_id: observation.host_snapshot.details["boot_id"])
      .where("audit_timestamp >= ?", observation.last_observed_at)
      .where("transition_type IS NOT NULL OR (category = 'avc' AND checkpoint_invalidated_fields <> '[]'::jsonb)")
      .distinct.pluck(:transition_type, :checkpoint_invalidated_fields)
    new(observation.host_snapshot, evidence.flat_map { |type, mask| fields_for(type) | mask })
  end

  def initialize(snapshot, invalidated_fields = [])
    @selinux = snapshot&.details&.fetch("selinux", {}) || {}
    @invalidated_fields = invalidated_fields.uniq
  end

  def trusted?(field)
    raise ArgumentError, "Unknown checkpoint dimension" unless FIELDS.include?(field.to_s)

    !@invalidated_fields.include?(field.to_s) && observed?(field.to_s)
  end

  def policy_identity
    @selinux["policy_identity"] if trusted?(:policy_identity)
  end

  def enforcement
    return @selinux["enforcement"] if trusted?(:enforcement)

    @selinux.key?("enforcement") || @invalidated_fields.include?("enforcement") ? "unknown" : nil
  end

  def booleans
    return [] if @invalidated_fields.include?("booleans") || %w[unknown unavailable].include?(@selinux["boolean_status"])

    Array(@selinux["booleans"])
  end

  def ports
    return { "status" => "unknown", "mappings" => [] } if @invalidated_fields.include?("ports")

    @selinux.dig("policy", "port_inventory") || { "status" => "unknown", "mappings" => [] }
  end

  def selinux
    values = @selinux.merge("policy_identity" => policy_identity, "enforcement" => enforcement,
      "policy" => @selinux.fetch("policy", {}).merge("port_inventory" => ports))
    if @invalidated_fields.include?("file_context_mappings")
      values["policy"] = values["policy"].merge("file_context_mappings_status" => "unknown", "file_contexts" => [], "local_file_context_mappings" => [], "file_context_equivalences" => [])
    end
    if @invalidated_fields.include?("booleans")
      values = values.merge("boolean_status" => "unknown", "booleans" => Array(@selinux["booleans"]).map { |entry| entry.merge("status" => "unknown", "current" => nil) })
    end
    values
  end

  def file_context_mappings
    return { "status" => "unknown", "mappings" => [], "local_mappings" => [], "equivalences" => [] } if @invalidated_fields.include?("file_context_mappings")

    policy = @selinux.fetch("policy", {})
    { "status" => policy["file_context_mappings_status"] || "unknown", "mappings" => Array(policy["file_contexts"]),
      "local_mappings" => Array(policy["local_file_context_mappings"]), "equivalences" => Array(policy["file_context_equivalences"]) }
  end

  # Same readiness rules in the bounded SQL activity projection; no per-row queries.
  def self.observed_fields_sql(details)
    identity = "#{details} #>> '{selinux,policy_identity}' ~ '^sha256:[0-9a-f]{64}$'"
    entries = "CASE WHEN jsonb_typeof(#{details} #> '{selinux,booleans}') = 'array' THEN #{details} #> '{selinux,booleans}' ELSE '[]'::jsonb END"
    booleans = <<~SQL.squish
      (#{details} #> '{selinux,booleans}' IS NULL OR jsonb_typeof(#{details} #> '{selinux,booleans}') = 'array') AND
      (#{details} #>> '{selinux,boolean_status}' = 'observed' OR
        (#{details} #>> '{selinux,boolean_status}' IS NULL AND jsonb_array_length(#{entries}) > 0))
      AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(#{entries}) b
        WHERE b->>'status' IS DISTINCT FROM 'observed' OR jsonb_typeof(b->'current') IS DISTINCT FROM 'boolean')
    SQL
    "array_remove(ARRAY[CASE WHEN #{identity} THEN 'policy_identity' END, CASE WHEN #{booleans} THEN 'booleans' END, " \
      "CASE WHEN #{details} #>> '{selinux,enforcement}' IN ('enforcing','permissive','disabled') THEN 'enforcement' END, " \
      "CASE WHEN #{details} #>> '{selinux,policy,port_inventory,status}' = 'observed' AND jsonb_typeof(#{details} #> '{selinux,policy,port_inventory,mappings}') = 'array' THEN 'ports' END, " \
      "CASE WHEN #{details} #>> '{selinux,policy,file_context_mappings_status}' = 'observed' AND jsonb_typeof(#{details} #> '{selinux,policy,file_contexts}') = 'array' AND jsonb_typeof(#{details} #> '{selinux,policy,local_file_context_mappings}') = 'array' AND jsonb_typeof(#{details} #> '{selinux,policy,file_context_equivalences}') = 'array' THEN 'file_context_mappings' END], NULL)"
  end

  def self.transition_fields_sql(column)
    "CASE #{column} " + TRANSITION_FIELDS.map { |type, fields| "WHEN '#{type}' THEN ARRAY[#{fields.map { |field| "'#{field}'" }.join(',')}]::text[]" }.join(" ") + " ELSE ARRAY[]::text[] END"
  end

  private

  def observed?(field)
    case field
    when "policy_identity" then @selinux["policy_identity"].to_s.match?(PolicyArtifact::IDENTITY_FORMAT)
    when "enforcement" then %w[enforcing permissive disabled].include?(@selinux["enforcement"])
    when "booleans"
      return false unless @selinux["booleans"].nil? || @selinux["booleans"].is_a?(Array)

      entries = Array(@selinux["booleans"])
      (@selinux["boolean_status"] == "observed" || (!@selinux.key?("boolean_status") && entries.any?)) &&
        entries.all? { |entry| entry.is_a?(Hash) && entry["status"] == "observed" && (entry["current"] == true || entry["current"] == false) }
    when "ports" then ports["status"] == "observed" && ports["mappings"].is_a?(Array)
    when "file_context_mappings"
      policy = @selinux.fetch("policy", {})
      policy["file_context_mappings_status"] == "observed" && %w[file_contexts local_file_context_mappings file_context_equivalences].all? { |key| policy[key].is_a?(Array) }
    end
  end
end
