class AvcNormalizer
  REQUIRED = %w[scontext tcontext tclass].freeze
  AVC_TYPES = %w[AVC USER_AVC].freeze
  NETWORK_PERMISSIONS = %w[connectto name_bind name_connect node_bind recvfrom sendto].freeze

  def self.call(records)
    new(records).call
  end

  def initialize(records)
    @records = records
  end

  def call
    parsed = @records.map { |record| parse_record(record) }
    avc_records = parsed.select { |record| AVC_TYPES.include?(record[:type_name]) }
    return [{ status: "ungroupable", missing: ["avc"] }] if avc_records.empty?

    supplemental = parsed.reject { |record| AVC_TYPES.include?(record[:type_name]) }
    fields = avc_records.map { |record| record[:fields] }.reduce({}) { |combined, record| combined.merge(record) }
    supplemental.each do |record|
      record[:fields].each { |key, value| fields[key] ||= value if %w[comm exe].include?(key) }
    end

    missing = REQUIRED.reject { |key| fields[key] }
    permissions = avc_records.flat_map { |record| record[:permissions] }.uniq
    missing << "permissions" if permissions.empty?
    missing << "source_type" unless context_type(fields["scontext"])
    missing << "target_type" unless context_type(fields["tcontext"])
    return [{ status: "ungroupable", missing: missing.uniq }] if missing.any?

    target_evidence = parsed.each_with_object({ path_fields: [], filesystem_paths: [], object_names: [] }) do |record, evidence|
      evidence[:path_fields].concat(record[:path_fields])
      evidence[:filesystem_paths].concat(record[:filesystem_paths])
      evidence[:object_names].concat(record[:object_names])
    end.transform_values(&:uniq)
    network_evidence = parsed.each_with_object(network_evidence_defaults) do |record, evidence|
      record_fields = record[:fields]
      evidence["dest_fields"].concat(Array(record_fields["dest"]))
      evidence["dport_fields"].concat(Array(record_fields["dport"]))
      evidence["lport_fields"].concat(Array(record_fields["lport"]))
      evidence["proto_fields"].concat(Array(record_fields["proto"] || record_fields["protocol"]))
      evidence["bind_port_fields"].concat(Array(record_fields["src"])) if record[:permissions].include?("name_bind")
      evidence["operations"].concat(record[:permissions] & NETWORK_PERMISSIONS)
    end.transform_values(&:uniq)
    process_evidence = parsed.each_with_object(process_evidence_defaults) do |record, evidence|
      record_fields = record[:fields]
      evidence["pids"].concat(Array(record_fields["pid"]))
      evidence["commands"].concat(Array(record_fields["comm"]))
      evidence["executables"].concat(Array(record_fields["exe"]))
      evidence["source_contexts"].concat(Array(record_fields["scontext"]))
    end.transform_values(&:uniq)

    [{
      status: "ok",
      source_context: fields["scontext"],
      source_type: context_type(fields["scontext"]),
      target_context: fields["tcontext"],
      target_type: context_type(fields["tcontext"]),
      target_class: fields["tclass"],
       permissions: permissions,
       permissive: permissive_state(fields["permissive"]),
       syscall_evidence: parsed.filter_map do |record|
         next unless record[:fields]["syscall"]
         record[:fields].slice("syscall", "success", "exit")
       end,
      command: fields["comm"],
      executable: fields["exe"],
      target_paths: target_evidence[:filesystem_paths],
      target_evidence: target_evidence,
      network_evidence: network_evidence,
      process_evidence: process_evidence,
       evidence_provenance: parsed.flat_map { |record| record[:provenance] }.uniq
    }]
  end

  private

  def parse_record(record)
    payload = record.respond_to?(:payload) ? record.payload : record
    type_name = record.respond_to?(:type_name) ? record.type_name : type_from_payload(payload)
    text = payload.to_s
    permissions = text[/\bdenied\b\s*\{([^}]*)\}/, 1].to_s.split
    {
      type_name: type_name,
      position: record.respond_to?(:position) ? record.position : nil,
      fields: key_values(text),
      permissions: permissions,
      path_fields: key_values(text).values_at("path").compact,
      filesystem_paths: filesystem_paths(type_name, key_values(text)),
      object_names: key_values(text).values_at("name").compact,
      provenance: provenance(type_name, record.respond_to?(:position) ? record.position : nil, key_values(text), permissions, text)
    }
  end

  def type_from_payload(payload)
    type = payload.to_s[/\btype=(\w+)/, 1]
    return type if type
    payload.to_s.match?(/\buser_avc\b/i) ? "USER_AVC" : "AVC"
  end

  def filesystem_paths(type_name, fields)
    paths = Array(fields["path"])
    paths += Array(fields["name"]) if type_name == "PATH"
    paths.select { |path| path.start_with?("/") }
  end

  def provenance(type_name, position, fields, permissions, text)
    field_kinds = {
      "exe" => "executable", "comm" => "command", "pid" => "pid", "scontext" => "source_context",
      "tcontext" => "target_context", "path" => "path", "name" => "object_name", "dest" => "dest",
      "dport" => "dport", "lport" => "lport", "proto" => "protocol", "protocol" => "protocol"
    }
    values = field_kinds.flat_map do |field, kind|
      Array(fields[field]).map { |value| evidence_item(kind, value, type_name, position) }
    end
    if permissions.include?("name_bind")
      values.concat(Array(fields["src"]).map { |value| evidence_item("bind_port", value, type_name, position) })
    end
    values.concat(text[/\bdenied\b\s*\{([^}]*)\}/, 1].to_s.split.map { |permission| evidence_item("permission", permission, type_name, position) })
  end

  def evidence_item(kind, value, type_name, position)
    { "kind" => kind, "value" => value, "source_record_type" => type_name, "source_record_position" => position, "temporal_scope" => "occurrence", "certainty" => "observed" }
  end

  def key_values(raw)
    raw.scan(/(\w+)=("(?:\\.|[^"])*"|\S+)/).to_h do |key, value|
      [key, value.start_with?("\"") ? value[1...-1].gsub('\\"', '"').gsub("\\\\", "\\") : value]
    end
  end

  def context_type(context)
    parts = context.to_s.split(":", 4)
    parts.length == 4 && parts[2].present? ? parts[2] : nil
  end

  def permissive_state(value)
    return true if value == "1"
    return false if value == "0"

    nil
  end

  def network_evidence_defaults
    { "dest_fields" => [], "dport_fields" => [], "lport_fields" => [], "proto_fields" => [], "bind_port_fields" => [], "operations" => [] }
  end

  def process_evidence_defaults
    { "pids" => [], "commands" => [], "executables" => [], "source_contexts" => [] }
  end
end
