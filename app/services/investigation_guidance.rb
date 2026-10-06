class InvestigationGuidance
  def self.call(issue:, occurrence: nil, intelligence: nil)
    new(issue, occurrence, intelligence).call
  end

  def initialize(issue, occurrence = nil, intelligence = nil)
    @issue = issue
    @occurrence = occurrence
    @intelligence = intelligence
  end

  def call
    occurrences = @occurrence ? [ @occurrence ] : @issue.occurrences.includes(:normalized_denial, :raw_event).to_a
    denials = occurrences.map(&:normalized_denial)
    evidence = denials.map { |denial| denial.details.fetch("target_evidence", {}) }
    paths = denials.each_with_index.flat_map { |denial, index| Array(evidence[index]["filesystem_paths"]).presence || Array(denial.target_paths) }.uniq
    names = evidence.flat_map { |value| Array(value["object_names"]) }.uniq
    network = denials.map { |denial| network_evidence(denial.details) }.reduce(network_defaults) { |combined, value| combined.to_h { |key| [key, (combined[key] + value[key]).uniq] } }
    process = denials.map { |denial| process_evidence(denial) }.reduce(process_defaults) { |combined, value| combined.to_h { |key| [key, (combined[key] + value[key]).uniq] } }
    event_file_contexts = denials.each_with_index.flat_map { |denial, index| RawEvent.effective_context_observations(denial.details["event_file_contexts"], occurrences[index].try(:raw_event).try(:checkpoint_invalidated_fields)) }
    expected_context_observations = occurrences.flat_map do |occurrence|
      raw = occurrence.try(:raw_event)
      RawEvent.effective_context_observations(raw&.file_context_observations, raw.try(:checkpoint_invalidated_fields)).select { |item| item["kind"] == "expected_context" }
    end
    provenance = denials.flat_map { |denial| Array(denial.details["evidence_provenance"]) }
    permissions = @occurrence ? denials.first.permissions : @issue.permissions
    executables = process["executables"]
    observations = [
      observation("Observed denied permissions across this issue: #{permissions.join(', ')} on #{@issue.target_class} objects.", @occurrence ? "avc_record" : "issue_occurrences", "observed"),
      *paths.map { |path| observation("The audit record contains the path #{path}.", basis_for(provenance, "path", path, "avc_record"), "observed") },
      *names.map { |name| observation("The audit record contains the object name #{name}; its complete path is not established.", basis_for(provenance, "object_name", name, "avc_record"), "observed") },
      *network_observations(network, provenance),
      *process_observations(process, provenance),
      *file_context_observations(event_file_contexts),
      *expected_context_observations(expected_context_observations)
    ]
    filesystem_target = %w[file dir lnk_file fifo_file chr_file blk_file sock_file].include?(@issue.target_class)
    checks = filesystem_target ? paths.flat_map do |path|
      [
        check(:current_file_label, path, "Compare the current label with the target type recorded by SECentral.", "A difference may be relevant; this does not prove the cause.", :current_state_only),
        check(:expected_file_label, path, "Check the label currently expected by installed policy.", "A difference from the current label may indicate a labeling issue.", :current_state_only),
        check(:parent_file_label, File.dirname(path), "Check the parent directory label and its expected policy context.", "A parent-label difference may affect access to the file; this does not prove the cause.", :current_state_only)
      ]
    end : []
    checks << check(:identify_object, nil, "Identify the complete object before running path-specific checks.", "A name alone cannot establish a full path.", :incomplete_target) if names.any? && paths.empty?
    if @occurrence
      checks << check(:audit_history, nil, "Look for additional surrounding AVC records if local audit retention covers the event timestamp.", "Additional records may provide context; use the host's local time for the search.", :historical_retention)
    end
    if %w[capability cap_userns].include?(@issue.target_class)
      observations << observation("The source domain was denied the #{permissions.join(', ')} capability.", "avc_record", "observed")
      checks.reject! { |check| %i[current_file_label expected_file_label parent_file_label].include?(check[:kind]) }
    end
    if @occurrence && executables.one?
      checks << check(:executable_context, executables.fetch(0), "Compare the observed executable and source context with the current process or service configuration.", "The current executable and context may differ from the state recorded at occurrence time.", :current_state_only)
    elsif @occurrence && executables.many?
      observations << observation("Multiple executable values were captured for this occurrence; no single executable was selected for a concrete check.", "avc_record", "observed")
    end
    if @issue.target_class.to_s.end_with?("_socket")
      observations << observation("The denial concerns a #{@issue.target_class} interaction between SELinux domains.", "avc_record", "observed")
      checks << check(:socket_context, nil, "Inspect the service and socket relationship using the captured domains and operation.", "The current service/socket state may explain whether the interaction is still present.", :current_state_only) if @occurrence
    end
    observations.concat(fleet_observations) unless @occurrence
    missing = missing_evidence(paths, names, filesystem_target)
    raw_event = @occurrence.try(:raw_event)
    if raw_event && filesystem_target && paths.present? && expected_context_observations.none? { |item| item["status"] == "resolved" } &&
        raw_event.raw_audit_records.where(record_type: [ 1400, 1107 ]).count > 1
      missing << "unambiguous AVC-to-path correlation; expected-context lookup was not run because the event contains multiple AVC records"
    end
    if @occurrence && filesystem_target && paths.present? &&
        expected_context_observations.none? { |item| item["status"] == "resolved" } &&
        event_file_contexts.none? { |item| item["expected_status"] == "observed" }
      missing << "resolved event-linked expected-context observation; no result is retained for this AVC/path/type"
    end
    { summary: "Investigation checks based on retained evidence; no diagnosis is implied.", observations: observations, checks: checks, missing_evidence: missing, historical_limitations: [ "Current host labels and policy may differ from the state at occurrence time." ] }
  end

  private

  def observation(text, basis, certainty)
    { observation: text, basis: basis, certainty: certainty }
  end

  def check(kind, target, reason, expected, limitation, extra = {})
    { kind: kind, target: target, reason: reason, expected: expected, limitation: limitation }.merge(extra)
  end

  def missing_evidence(paths, names, filesystem_target)
    if filesystem_target && paths.empty?
      return [ names.any? ? "complete absolute target path from retained audit evidence; expected-context lookup was not run" : "absolute filesystem path from retained audit evidence; expected-context lookup was not run" ]
    end
    return [ "unambiguous absolute path-to-denied-object correlation; expected-context lookup was not run" ] if @occurrence && paths.many?

    []
  end

  def network_evidence(details)
    details.to_h.fetch("network_evidence", {}).reverse_merge(network_defaults)
  end

  def network_defaults
    { "dest_fields" => [], "dport_fields" => [], "lport_fields" => [], "proto_fields" => [], "bind_port_fields" => [], "operations" => [] }
  end

  def network_observations(network, provenance)
    {
      "dest_fields" => ["dest field", "dest"],
      "dport_fields" => ["dport field", "dport"],
      "lport_fields" => ["lport field", "lport"],
      "proto_fields" => ["protocol field", "protocol"],
      "bind_port_fields" => ["bind port field", "bind port"],
      "operations" => ["network operation", "permission"]
    }.flat_map { |key, (label, kind)| network[key].map { |value| observation("The audit record contains #{label} #{value}.", basis_for(provenance, kind, value, "avc_record"), "observed") } }
  end

  def process_evidence(denial)
    evidence = denial.details.to_h.fetch("process_evidence", {}).reverse_merge(process_defaults)
    evidence["commands"] = [ denial.try(:command) ].compact if evidence["commands"].empty?
    evidence["executables"] = [ denial.try(:executable) ].compact if evidence["executables"].empty?
    evidence["source_contexts"] = [ denial.try(:source_context) ].compact if evidence["source_contexts"].empty?
    evidence
  end

  def process_defaults
    { "pids" => [], "commands" => [], "executables" => [], "source_contexts" => [] }
  end

  def process_observations(process, provenance)
    {
      "pids" => "process ID",
      "commands" => "command",
      "executables" => "executable",
      "source_contexts" => "source context"
    }.flat_map { |key, label| process[key].map { |value| observation("The audit record contains #{label} #{value}.", basis_for(provenance, key.delete_suffix("s"), value, "avc_record"), "observed") } }
  end

  def file_context_observations(observations)
    observations.filter_map do |item|
      next unless item["path"].present?
      text = if item["status"] == "observed"
        expected = item["expected_status"] == "observed" ? " Current policy expects #{item["expected_context"]}." : ""
        "The event-associated filesystem label for #{item["path"]} was #{item["context"]}.#{expected}"
      else
        "The event-associated filesystem label for #{item["path"]} was not available (#{item["status"]})."
      end
      observation(text, "occurrence_file_context_evidence", "observed")
    end
  end

  def expected_context_observations(observations)
    observations.filter_map do |item|
      next unless item["path"].present?

      text = if item["status"] == "resolved"
        "At #{item["observed_at"]}, matchpathcon resolved #{item["path"]} as #{item["expected_context"]} for a #{item["file_type"]}; this is inspection-time configuration evidence, not proof of the result at AVC time."
      else
        "Expected file context for #{item["path"]} was #{item["status"]} (#{item["reason"]})."
      end
      observation(text, "expected_context_observation", "observed")
    end
  end

  def basis_for(provenance, kind, value, fallback)
    source = provenance.find { |item| item["kind"] == kind && item["value"] == value }
    source ? "#{source["source_record_type"].downcase}_record" : fallback
  end

  def fleet_observations
    intelligence = @intelligence || IssueIntelligence.call(@issue)
    fleet = intelligence.fetch(:fleet)
    observations = [ observation("#{fleet[:hosts_with_occurrence]} of #{fleet[:current_configuration_hosts]} hosts with fresh heartbeat-confirmed configuration have an occurrence for this issue; #{fleet[:hosts_without_occurrence]} do not.", "fleet_comparison", "derived") ]
    with_occurrence = fleet[:with_occurrence_modules] || {}
    without_occurrence = fleet[:without_occurrence_modules] || {}
    (with_occurrence.keys | without_occurrence.keys).each do |module_info|
      with_occurrence_count = with_occurrence.fetch(module_info, 0)
      without_occurrence_count = without_occurrence.fetch(module_info, 0)

      name, priority, provenance = module_info
      label = provenance == "custom" ? "Custom module" : "Module"
      observations << observation("#{label} #{name} (priority #{priority}, provenance #{provenance}) is present on #{prevalence(with_occurrence_count, fleet[:hosts_with_occurrence])} with an occurrence and #{prevalence(without_occurrence_count, fleet[:hosts_without_occurrence])} without one. Investigate whether this policy difference is relevant.", "fleet_comparison", "derived")
    end
    matches = intelligence.fetch(:current_file_context_matches, [])
    matches.group_by { |item| [item[:path], item[:mapping]["context"]] }.each do |(path, context), values|
      observations << observation("Current policy maps #{path} to #{context} on #{values.size} hosts with fresh heartbeat-confirmed configuration; this is expected-context evidence, not a current file-label measurement.", "current_configuration_fleet", "derived")
    end
    observations
  end

  def prevalence(count, total)
    total.zero? ? "no hosts" : "#{count}/#{total} hosts"
  end
end
