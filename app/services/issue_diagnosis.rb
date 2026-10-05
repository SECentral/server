class IssueDiagnosis
  def self.call(issue, intelligence: nil)
    new(issue, intelligence || IssueIntelligence.call(issue)).call
  end

  def self.per_host(issue, intelligence: nil)
    new(issue, intelligence || IssueIntelligence.call(issue)).per_host
  end

  def initialize(issue, intelligence)
    @issue = issue
    @intelligence = intelligence
  end

  def call
    candidate = mismatch_candidate
    return file_context_diagnosis(candidate) if candidate

    candidate = no_matching_allow_candidate
    return no_matching_allow_diagnosis(candidate) if candidate

    candidate = conditional_allow_candidate
    return unless candidate

    conditional_allow_diagnosis(candidate)
  end

  def per_host
    return @per_host if @per_host

    evaluations = @intelligence[:policy_evaluation].to_h.fetch(:occurrence_evaluations, []).index_by { |item| item[:occurrence_id] }
    results = occurrences.map do |occurrence|
      evaluation = evaluations[occurrence.id] || { status: "unavailable", occurrence_id: occurrence.id, host_id: occurrence.host_id }
      findings = findings_for_occurrence(occurrence, evaluation)
      diagnosis = findings.first
      { occurrence_id: occurrence.id, host_id: occurrence.host_id, status: diagnosis ? "diagnosed" : "insufficient_evidence",
        diagnosis: diagnosis, findings: findings,
        agreement_signature: findings.map { |finding| agreement_signature(occurrence, evaluation, finding) } }
    end

    @per_host = results.group_by { |result| result[:host_id] }.map do |host_id, occurrence_diagnoses|
      host = occurrences.find { |occurrence| occurrence.host_id == host_id }.host
      diagnosed = occurrence_diagnoses.select { |result| result[:diagnosis] }
      signatures = diagnosed.map { |result| result[:agreement_signature] }.uniq
      status = if diagnosed.empty? || diagnosed.size != occurrence_diagnoses.size
        "insufficient_evidence"
      elsif signatures.one?
        "agreement"
      else
        "disagreement"
      end
      { host_id: host_id, hostname: host.hostname, status: status,
        diagnosis: status == "agreement" ? diagnosed.first[:diagnosis] : nil,
        occurrence_diagnoses: occurrence_diagnoses }
    end
  end

  def finding_summaries
    evaluations = @intelligence[:policy_evaluation].to_h.fetch(:occurrence_evaluations, []).index_by { |item| item[:occurrence_id] }
    entries = per_host.flat_map { |host| host[:occurrence_diagnoses] }.flat_map do |item|
      item[:findings].map do |finding|
        signature = agreement_signature(occurrences_by_id.fetch(item[:occurrence_id]), evaluations[item[:occurrence_id]] || {}, finding)
        { diagnosis: finding, signature: signature }
      end
    end
    entries.group_by { |item| item[:signature] }.values.map do |group|
      finding = group.first[:diagnosis]
      observations = group.filter_map { |item| item[:diagnosis][:observation_event_id] }.uniq
      reused = group.count do |item|
        evidence = item[:diagnosis]
        evidence[:observation_event_id] && evidence[:observation_event_id] != occurrences_by_id.fetch(evidence[:occurrence_id]).raw_event_id
      end
      { diagnosis: finding, occurrence_count: group.size, observation_count: observations.size,
        reused_observation_occurrences: reused }
    end.sort_by { |item| [ %w[file_context_mismatch no_matching_allow conditional_allow_inactive].index(item[:diagnosis][:kind]), -occurrences_by_id.fetch(item[:diagnosis][:occurrence_id]).occurred_at.to_f ] }
  end

  def file_context_diagnosis(candidate)
    {
       kind: "file_context_mismatch",
      occurrence_id: candidate[:occurrence_id],
      host_id: candidate[:host_id],
      process_command: candidate["process_command"],
      executable: candidate["executable"],
      title: "Potential file-context mismatch",
      evidence_strength: "moderate",
      finding: "The AVC target type differs from the expected file-context type observed later.",
      path: candidate[:path],
      observed_type: candidate[:observed_type],
      expected_type: candidate[:expected_type],
      observed_context: candidate[:observed_context],
      expected_context: candidate[:expected_context],
      file_type: candidate[:file_type],
      expected_context_observed_at: candidate[:observed_at],
      expected_context_resolver: candidate[:resolver],
      observation_event_id: candidate[:raw_event_id],
      source_domain: @issue.source_type,
      permissions: @issue.permissions,
      target_class: candidate[:object_class],
      evidence: [
        { fact: "At AVC time, SELinux recorded the denied object label as #{candidate[:observed_context]} (#{candidate[:observed_type]}).", basis: "avc_record", certainty: "observed" },
        { fact: "At #{candidate[:observed_at]}, matchpathcon resolved #{candidate[:path]} as #{candidate[:expected_context]} for a #{candidate[:file_type]}.", basis: "expected_context_observation", certainty: "observed" },
        { fact: "#{@issue.source_type} was denied #{@issue.permissions.join(', ')} access to #{candidate[:path]}.", basis: "avc_record", certainty: "observed" }
      ],
      interpretation: "The label recorded in the AVC differs by type from what the host's SELinux file-context configuration resolved when SECentral inspected the path. This difference may help explain the denial.",
      limitation: "Expected context was inspected after the AVC and does not prove the same configuration applied at AVC time or that this path and label are appropriate for the workload.",
      next_step: "Confirm that this path and its expected label are appropriate for the workload before considering any labeling change.",
      policy_guidance: "This observation does not authorize relabeling, custom file-context rules, broader access, or policy changes.",
      temporal_scope: "avc_vs_expected_context_inspection"
    }.compact
  end

  private

  def occurrences
    @occurrences ||= begin
      scope = @issue.occurrences
      scope.respond_to?(:includes) ? scope.includes(:host, :normalized_denial, :raw_event).order(occurred_at: :desc, id: :desc).to_a : scope
    end
  end

  def occurrences_by_id
    @occurrences_by_id ||= occurrences.index_by(&:id)
  end

  def findings_for_occurrence(occurrence, evaluation)
    findings = []
    candidate = occurrence_mismatch_candidate(occurrence)
    findings << file_context_diagnosis(candidate).merge(occurrence_id: occurrence.id, host_id: occurrence.host_id) if candidate

    candidate = no_matching_allow_candidate_for(occurrence, evaluation)
    if candidate
      findings << no_matching_allow_diagnosis(candidate).merge(host_id: occurrence.host_id)
    elsif (candidate = conditional_allow_candidate_for(occurrence, evaluation))
      findings << conditional_allow_diagnosis(candidate).merge(host_id: occurrence.host_id)
    end
    findings
  end

  def no_matching_allow_candidate
    evaluation = @intelligence[:policy_evaluation].to_h
    Array(evaluation[:occurrence_evaluations]).filter_map do |item|
      next unless item[:occurrence_id].present? && item[:rule_state] == "no_matching_allow"

       occurrence = occurrences_by_id[item[:occurrence_id]]
       no_matching_allow_candidate_for(occurrence, item)
     end.first
  end

  def no_matching_allow_diagnosis(candidate)
    denial = candidate[:denial]
    permissions = candidate[:permissions]
    target = "#{@issue.target_type}:#{@issue.target_class}"
    target_noun = @issue.target_class == "file" ? "a file labeled #{@issue.target_type}" : "an #{@issue.target_class} labeled #{@issue.target_type}"
    evidence = denial.details.to_h.fetch("target_evidence", {})
    paths = Array(evidence["filesystem_paths"])
    names = Array(evidence["object_names"])
    object_guidance = if paths.present? && (permissions & %w[execute entrypoint]).any?
      "Confirm whether this workload is expected to start #{paths.one? ? paths.first : "this executable"} before considering any policy change."
    elsif paths.present? && candidate[:denial].command.present?
      "Confirm that #{candidate[:denial].command} is configured to access #{paths.one? ? paths.first : "this object"} and that the access is intended before investigating its label or policy."
    elsif paths.present?
      "Confirm the object's identity and intended access before investigating its current label or file-context configuration."
    elsif names.present?
      "Identify and confirm the full path for #{names.one? ? names.first : "the recorded objects"} before investigating path-specific labeling or file-context configuration."
    else
      "Identify and confirm the full object path before investigating path-specific labeling or file-context configuration."
    end

    {
      kind: "no_matching_allow",
      title: "No matching SELinux allow was found for this access",
      evidence_strength: "strong",
      occurrence_id: candidate[:occurrence].id,
      host_id: candidate[:item][:host_id] || (candidate[:occurrence].host_id if candidate[:occurrence].respond_to?(:host_id)),
      source_domain: @issue.source_type,
      source_description: @issue.source_type,
      permissions: permissions,
      target_type: @issue.target_type,
      target_class: @issue.target_class,
      path: paths.one? ? paths.first : nil,
      enforcement_mode: candidate[:item][:enforcement_mode],
      syscall_failed: candidate[:item][:enforcement_mode] == "enforcing" && failed_syscall?(denial.details.to_h.fetch("syscall_evidence", [])),
      finding: "No matching allow was found for the observed denied permission.",
      **policy_provenance(candidate[:item]),
      process_command: (candidate[:denial].command if candidate[:denial].respond_to?(:command)),
      executable: (candidate[:denial].executable if candidate[:denial].respond_to?(:executable)),
      lead: "The SELinux domain #{@issue.source_type} was denied #{permissions.join(' and ')} access to #{target_noun}. SECentral found no matching allow for the denied #{permissions.join(' and ')} access in the evaluated policy.",
      evidence: [
        { fact: "#{@issue.source_type} was denied #{permissions.join(', ')} on #{target}.", basis: "avc_record", certainty: "observed" },
        { fact: "The exact policy artifact has no matching allow for the observed denied permission.", basis: "reusable_policy_fact", certainty: "derived" }
      ],
      interpretation: "No matching allow explains the observed policy denial, but it does not establish why this workload should or should not receive the access.",
      next_step: object_guidance,
      limitation: "No matching allow does not establish a wrong target label, required custom policy, or intended workload access.",
      policy_guidance: "Review the object identity, workload intent, labels, constraints, and policy evidence before making any change. This finding does not authorize a policy, labeling, boolean, or enforcement change.",
      temporal_scope: "correlated_occurrence_state",
      evaluations: candidate[:item][:evaluations]
    }.compact
  end

  def conditional_allow_candidate
    evaluation = @intelligence[:policy_evaluation].to_h
    occurrence_evaluations = Array(evaluation[:occurrence_evaluations])
    candidates = occurrence_evaluations.filter_map do |item|
       occurrence = occurrences_by_id[item[:occurrence_id]]
       conditional_allow_candidate_for(occurrence, item)
     end
    candidates.sort_by { |candidate| candidate[:item][:enforcement_mode] == "enforcing" ? 0 : 1 }.first
  end

  def conditional_allow_diagnosis(candidate)
    item = candidate[:item]
    denial = candidate[:denial]
    network = denial.details.to_h.fetch("network_evidence", {})
    operation = candidate[:operation]
    if operation == "read"
      paths = Array(denial.details.to_h.dig("target_evidence", "filesystem_paths"))
      key = [ item[:evaluations], item[:booleans], candidate[:conditional_rules], item[:enforcement_mode], paths,
        denial.command, denial.executable, failed_syscall?(denial.details.to_h["syscall_evidence"]) ]
      @read_findings ||= {}
      template = @read_findings[key] ||= file_access_diagnosis(candidate).except(:occurrence_id, :checkpoint_observed_at)
      return template.merge(occurrence_id: item[:occurrence_id], checkpoint_observed_at: item[:checkpoint_observed_at])
    end
    return file_access_diagnosis(candidate) if operation == "execute"

    connect = operation == "name_connect"
    permissions = denial.permissions
    ports = connect ? IssueIntelligence.destination_ports(denial.details) : Array(network["bind_port_fields"]).uniq
    port = ports.one? ? ports.first : nil
    enforcing = item[:enforcement_mode] == "enforcing"
    blocked = enforcing && failed_syscall?(denial.details.to_h.fetch("syscall_evidence", []))
    {
      kind: "conditional_allow_inactive",
      operation: operation,
      title: if connect
        blocked ? "SELinux blocked a network connection request" : enforcing ? "SELinux denied a network connection request" : "SELinux reported a network connection denial"
      else
        blocked ? "SELinux blocked a local port bind request" : enforcing ? "SELinux denied a local port bind request" : "SELinux reported a local port bind denial"
      end,
      evidence_strength: "strong",
      finding: "Matching conditional allow paths exist, but their conditions were inactive at the associated host checkpoint.",
      occurrence_id: item[:occurrence_id],
      source_domain: @issue.source_type,
      source_description: @issue.source_type,
      permission: permissions.first,
      bind_port: connect ? nil : port,
      target_type: @issue.target_type,
      target_class: @issue.target_class,
      destination_port: connect ? port : nil,
      enforcement_mode: item[:enforcement_mode],
      permissive: item[:permissive],
      syscall_failed: blocked,
      conditional_rules: candidate[:conditional_rules],
      condition_boolean_states: condition_boolean_states(item, candidate[:conditional_rules]),
      booleans: item[:booleans],
      **policy_provenance(item),
      evaluations: item[:evaluations],
      process_command: (denial.command if denial.respond_to?(:command)),
      executable: (denial.executable if denial.respond_to?(:executable)),
      evidence: [
        { fact: "#{@issue.source_type} attempted #{permissions.join(', ')} on #{@issue.target_type}:#{@issue.target_class}#{port ? " at TCP port #{port}" : ""}.", basis: "avc_record", certainty: "observed" },
        { fact: "The matching conditional allow paths evaluated inactive at the associated host checkpoint.", basis: "reusable_policy_fact_and_checkpoint_state", certainty: "derived" },
        { fact: enforcing ? (blocked ? "SELinux was enforcing and the correlated syscall failed." : "SELinux was enforcing; syscall outcome was unavailable.") : "SELinux reported that this operation would be denied under enforcement.", basis: "occurrence_state", certainty: "observed" }
      ],
      interpretation: "Under the observed checkpoint state, these conditional paths did not provide the denied permission. That is consistent with the denial, not proof of its only cause.",
      limitation: "Whether this workload should have the network capability is a workload and security decision; this finding does not authorize changing policy or enabling a boolean.",
      next_step: connect ? "Confirm whether this workload is expected to connect to TCP port #{port || "the recorded destination"}. Review the relevant SELinux conditional policy and its scope before changing policy state." : "Confirm whether this workload is expected to bind TCP port #{port || "the recorded local port"}. Review the relevant SELinux conditional policy and its scope before changing policy state.",
      temporal_scope: "correlated_occurrence_state"
    }.compact
  end

  def conditional_operation(denial, item)
    return "read" if denial.target_class == "file" && Array(denial.permissions) == [ "read" ]

    operation = Array(denial.permissions).intersection(%w[name_connect name_bind execute])
    return unless operation.one?
    return operation.first if operation.first != "execute"
    return unless Array(item[:evaluations]).any? { |fact| Array(fact["permissions"]).include?(operation.first) && fact["result"] == "matched" }

    operation.first
  end

  def operation_conditional_rules(item, operation)
    return Array(item[:conditional_rule_states]) unless %w[execute read].include?(operation)

    rules = Array(item[:evaluations]).select { |fact| Array(fact["permissions"]).include?(operation) }.flat_map { |fact| Array(fact["matching_rules"]) }
    Array(item[:conditional_rule_states]).select { |rule| rules.include?(rule[:rule]) }
  end

  def file_access_diagnosis(candidate)
    item = candidate[:item]
    denial = candidate[:denial]
    read = candidate[:operation] == "read"
    evidence = denial.details.to_h.fetch("target_evidence", {})
    paths = Array(evidence["filesystem_paths"])
    path = paths.one? ? paths.first : nil
    enforcing = item[:enforcement_mode] == "enforcing"
    blocked = enforcing && failed_syscall?(denial.details.to_h.fetch("syscall_evidence", []))
    target = path || Array(evidence["object_names"]).first || "the recorded file"

    {
      kind: "conditional_allow_inactive",
      operation: candidate[:operation],
      title: read ? "A matching SELinux read rule was inactive" : blocked ? "SELinux blocked an execution request" : enforcing ? "SELinux denied an execution request" : "SELinux reported an execution denial",
      evidence_strength: "strong",
      finding: read ? "A matching SELinux read rule exists, but its condition was inactive at the associated host checkpoint." : blocked ? "SELinux blocked execution while a matching policy condition was inactive." : enforcing ? "SELinux denied execution while a matching policy condition was inactive." : "SELinux reported an execution denial while a matching policy condition was inactive.",
      occurrence_id: item[:occurrence_id],
      source_domain: @issue.source_type,
      source_description: @issue.source_type,
      permission: candidate[:operation],
      permissions: denial.permissions,
      target_type: @issue.target_type,
      target_class: @issue.target_class,
      path: path,
      enforcement_mode: item[:enforcement_mode],
      permissive: item[:permissive],
      syscall_failed: blocked,
      conditional_rules: candidate[:conditional_rules],
      condition_boolean_states: condition_boolean_states(item, candidate[:conditional_rules]),
      booleans: item[:booleans],
      **policy_provenance(item),
      evaluations: item[:evaluations],
      process_command: (denial.command if denial.respond_to?(:command)),
      executable: (denial.executable if denial.respond_to?(:executable)),
      evidence: [
        { fact: read ? "#{@issue.source_type} was denied read access to a file labeled #{@issue.target_type}." : "#{@issue.source_type} attempted to execute #{target}, labeled #{@issue.target_type}.", basis: "avc_record", certainty: "observed" },
        { fact: "A matching conditional allow for #{candidate[:operation]} exists, but its condition evaluated inactive in the correlated host state.", basis: "reusable_policy_fact_and_checkpoint_state", certainty: "derived" },
        { fact: enforcing ? (blocked ? "SELinux was enforcing and the correlated #{read ? "file-access" : "execve"} syscall failed." : "SELinux was enforcing; syscall outcome was unavailable.") : "SELinux reported that this operation would be denied under enforcement.", basis: "occurrence_state", certainty: "observed" }
      ],
      interpretation: "Under the observed checkpoint state, this conditional rule did not provide the denied permission. This is consistent with the denial, not proof of its only cause.",
      limitation: read ? "Boolean state comes from the associated checkpoint, not a measurement at AVC time. This does not establish the expected path label or whether the workload should receive access." : "This finding does not establish that a domain transition was attempted or intended, and does not authorize changing policy, labeling, or boolean state.",
      next_step: read ? "Confirm whether this workload is intended to read files labeled #{@issue.target_type}. Investigate the content's labeling and the intended scope of the matching conditional rule before considering a change." : "Confirm whether this workload is expected to execute this file. Review the relevant SELinux conditional policy and its scope before changing policy state.",
      temporal_scope: "correlated_occurrence_state"
    }.compact
  end

  def failed_syscall?(evidence)
    Array(evidence).any? { |syscall| %w[no false 0].include?(syscall["success"].to_s) }
  end

  def condition_boolean_states(item, rules = item[:conditional_rule_states])
    rules.map do |rule|
      names = rule[:expression].scan(/[A-Za-z0-9_]+/).uniq
      rule.merge(booleans: item[:booleans].select { |boolean| names.include?(boolean["name"]) })
    end
  end

  def policy_provenance(item)
    identities = Array(item[:policy_identity])
    { policy_identity: identities.one? ? identities.first : nil, checkpoint_observed_at: item[:checkpoint_observed_at] }
  end

  def mismatch_candidate
    mismatches = Array(@intelligence[:expected_context_observations]).filter_map do |item|
      expected_context_mismatch(item)
    end
    unique = mismatches.uniq { |item| [ item[:path], item[:host_id], item[:observed_type], item[:expected_type] ] }
    paths = unique.map { |item| item[:path] }.uniq
    signatures = unique.map { |item| [ item[:path], item[:observed_type], item[:expected_type] ] }.uniq
    return unless unique.one? && paths.one? && signatures.one?

    unique.first
  end

  def occurrence_mismatch_candidate(occurrence)
    observations = expected_context_observations_for(occurrence)
    mismatches = observations.filter_map { |item| expected_context_mismatch(item) }
    unique = mismatches.uniq { |item| [ item[:path], item[:observed_type], item[:expected_type] ] }
    unique.one? ? unique.first : nil
  end

  def expected_context_observations_for(occurrence)
    observations = Array(@intelligence[:expected_context_observations])
    direct = observations.select { |item| item[:occurrence_id] == occurrence.id }
    denial = occurrence.normalized_denial
    paths = Array(denial.details.to_h.dig("target_evidence", "filesystem_paths")).uniq
    candidates = if direct.any?
      direct
    elsif paths.one?
      observations.select do |item|
        item[:host_id] == occurrence.host_id && item["path"] == paths.first && item["object_class"] == denial.target_class &&
          item[:checkpoint_observed_at].present? && item[:checkpoint_observed_at] == occurrence.raw_event.host_observed_at &&
          item[:boot_id].present? && item[:boot_id] == occurrence.raw_event.boot_id
      end
    else
      []
    end

    candidates.map do |item|
      item.merge(
        "target_context" => denial.target_context,
        "target_class" => denial.target_class,
        "filesystem_paths" => paths,
        "process_command" => (denial.command if denial.respond_to?(:command)),
        "executable" => (denial.executable if denial.respond_to?(:executable)),
        occurrence_id: occurrence.id,
        avc_occurred_at: occurrence.occurred_at
      )
    end
  end

  def expected_context_mismatch(item)
    return unless item["status"] == "resolved" && item["path"].to_s.start_with?("/")
    return unless Array(item["filesystem_paths"]).include?(item["path"])
    return unless item["object_class"] == item["target_class"] && item["object_class"].present?
    return unless item["observed_at"].present? && item["expected_context"].present? && item["target_context"].present?
    return unless observed_after_avc?(item)

    observed_type = context_type(item["target_context"])
    expected_type = context_type(item["expected_context"])
    return unless observed_type.present? && observed_type == @issue.target_type && expected_type.present? && observed_type != expected_type

    {
      path: item["path"], host_id: item[:host_id], occurrence_id: item[:occurrence_id],
      "process_command" => item["process_command"], "executable" => item["executable"],
      raw_event_id: item[:raw_event_id], object_class: item["object_class"], file_type: item["file_type"],
      observed_context: item["target_context"], expected_context: item["expected_context"],
      observed_type: observed_type, expected_type: expected_type,
      observed_at: item["observed_at"], resolver: item["resolver"]
    }
  end

  def observed_after_avc?(item)
    item[:avc_occurred_at].present? && Time.iso8601(item["observed_at"]) > item[:avc_occurred_at].to_time
  rescue ArgumentError, TypeError
    false
  end

  def no_matching_allow_candidate_for(occurrence, item)
    return unless occurrence && item[:status] == "evaluated" && item[:rule_state] == "no_matching_allow"

    evaluations = Array(item[:evaluations])
    denial = occurrence.normalized_denial
    denied_permissions = Array(denial&.permissions)
    evaluated_permissions = evaluations.flat_map { |fact| Array(fact["permissions"]) }.uniq
    return if evaluations.empty? || evaluations.any? { |fact| fact["result"] != "no_match" }
    return unless denial && denial.source_type == @issue.source_type && denial.target_type == @issue.target_type && denial.target_class == @issue.target_class
    return unless denied_permissions.present? && (denied_permissions - evaluated_permissions).empty?

    { item: item, occurrence: occurrence, denial: denial, permissions: denied_permissions }
  end

  def conditional_allow_candidate_for(occurrence, item)
    return unless occurrence && item[:status] == "evaluated" && item[:policy_identity].is_a?(Array) && item[:policy_identity].one?
    return unless Array(item[:booleans]).all? { |boolean| boolean["status"] == "observed" && boolean["current"].in?([true, false]) }

    denial = occurrence.normalized_denial
    return unless denial && denial.source_type == @issue.source_type && denial.target_type == @issue.target_type && denial.target_class == @issue.target_class

    operation = conditional_operation(denial, item)
    return unless operation
    return if operation != "execute" && item[:rule_state] != "conditional_inactive"
    if operation == "read"
      facts = Array(item[:evaluations]).select { |fact| Array(fact["permissions"]).include?("read") }
      return unless facts.present? && facts.all? { |fact| fact["result"] == "matched" && Array(fact["matching_rules"]).present? && Array(fact["matching_rules"]).all? { |rule| rule.include?("[") } }
    end

    conditional_rules = operation_conditional_rules(item, operation)
    return unless conditional_rules.present? && conditional_rules.all? { |rule| rule[:state] == "inactive" }

    { item: item, occurrence: occurrence, denial: denial, operation: operation, conditional_rules: conditional_rules }
  end

  def agreement_signature(occurrence, evaluation, diagnosis)
    return unless diagnosis

    case diagnosis[:kind]
    when "conditional_allow_inactive"
      { kind: diagnosis[:kind], source_type: occurrence.normalized_denial.source_type,
        target_type: diagnosis[:target_type], target_class: diagnosis[:target_class], permission: diagnosis[:permission],
        operation: diagnosis[:operation], endpoint: diagnosis[:destination_port] || diagnosis[:bind_port] || diagnosis[:path],
        enforcement_mode: diagnosis[:enforcement_mode], syscall_failed: diagnosis[:syscall_failed],
        policy_evidence: policy_evidence_signature(evaluation, [diagnosis[:permission]]),
        conditional_rules: Array(diagnosis[:conditional_rules]).map { |rule| rule.slice(:rule, :expression, :state) }.sort_by { |rule| rule[:rule].to_s },
        boolean_states: Array(diagnosis[:condition_boolean_states]).flat_map { |condition| Array(condition[:booleans]) }
          .map { |boolean| boolean.slice("name", "status", "current") }.uniq.sort_by { |boolean| boolean["name"] }
      }
    when "no_matching_allow"
      { kind: diagnosis[:kind], source_type: occurrence.normalized_denial.source_type,
        target_type: diagnosis[:target_type], target_class: diagnosis[:target_class], permissions: Array(diagnosis[:permissions]).sort,
        policy_evidence: policy_evidence_signature(evaluation, diagnosis[:permissions]) }
    when "file_context_mismatch"
      candidate = occurrence_mismatch_candidate(occurrence)
      { kind: diagnosis[:kind], source_type: occurrence.normalized_denial.source_type,
        target_type: occurrence.normalized_denial.target_type, target_class: occurrence.normalized_denial.target_class,
        permissions: Array(occurrence.normalized_denial.permissions).sort, path: diagnosis[:path],
        observed_type: candidate&.fetch(:observed_type), expected_type: candidate&.fetch(:expected_type) }
    end
  end

  def policy_evidence_signature(evaluation, permissions)
    Array(evaluation[:evaluations]).select { |fact| (Array(fact["permissions"]) & Array(permissions)).any? }.map do |fact|
      fact.slice("result", "provenance", "limitations", "constraints").merge(
        "permissions" => (Array(fact["permissions"]) & Array(permissions)).sort,
        "matching_rules" => Array(fact["matching_rules"]).sort
      )
    end.sort_by { |fact| [fact["policy_identity"], fact["evaluator_version"], fact["result"], fact["permissions"]] }
  end

  def context_type(context)
    context.to_s.split(":", 4)[2]
  end
end
