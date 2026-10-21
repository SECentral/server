require "digest"
require "pathname"
require "shellwords"

# Eligibility and commands live together on the server. No policy subprocesses.
class ResolutionCandidates
  VERSION = 1
  PLAN_SEMANTICS_VERSION = 1
  EXPECTED_CONTEXT_SEMANTICS_VERSION = 1
  FILE_REMEDY_SEMANTICS_VERSION = 2

  def initialize(issue, intelligence: nil, analyzer: nil)
    @issue = issue
    @intelligence = intelligence || IssueIntelligence.call(issue)
    @analyzer = analyzer || IssueDiagnosis.new(issue, @intelligence)
    @plans = {}
    @current_states = {}
    @facts = {}
    @occurrence_candidates = Hash.new { |hash, id| hash[id] = [] }
  end

  def call
    return @result if @result

    @rejected = [
      { kind: "persistent_fcontext", reason: "Effective local rules, substitutions and overlap/operation evidence are insufficient for a new persistent mapping." },
      { kind: "recursive_relabel", reason: "Evidence establishes individual objects, not a tree scope." }
    ]
    candidates = @analyzer.per_host.flat_map { |host| host[:occurrence_diagnoses] }.flat_map do |item|
      occurrence = occurrences.fetch(item[:occurrence_id])
      item[:findings].flat_map do |finding|
        case finding[:kind]
        when "file_context_mismatch" then [label_candidate(occurrence, finding)].compact
        when "conditional_allow_inactive" then boolean_candidates(occurrence, finding)
        else []
        end
      end
    end
    ports = PortMappingGuidance.new(@issue, occurrences: occurrences.values).call
    candidates.concat(ports[:proposals].map do |proposal|
      occurrence = occurrences.fetch(proposal[:occurrence_id])
      candidate = base(occurrence, { kind: "port_policy_alternative" }, "set_port_mapping", proposal[:resource]).merge(proposal[:candidate])
      finish(candidate, proposal[:basis], proposal[:semantic_basis], proposal[:plan], semantics_version: PortMappingGuidance::PLAN_SEMANTICS_VERSION)
    end)
    # Non-shared candidates retain their latest permission-specific example.
    candidates = candidates.group_by { |candidate| candidate[:id] }.values.map do |group|
      candidate = group.first
      if candidate[:supporting_observations]
        observations = group.flat_map { |item| item[:supporting_observations] }.uniq { |item| item[:occurrence_id] }
        candidate[:supporting_observations] = observations.group_by { |item| item.values_at(:issue_signature_id, :permissions) }.values.map do |items|
          items.first.merge(occurrence_count: items.size, enforcement_modes: items.flat_map { |item| item[:enforcement_modes] }.uniq.sort)
        end
        candidate[:evidence_basis] = candidate[:evidence_basis].merge(supporting_observations: candidate[:supporting_observations])
        @plans[candidate[:id]] = @plans.fetch(candidate[:id]).merge(evidence_basis: candidate[:evidence_basis])
      end
      candidate
    end
    @result = { candidates: candidates, rejected_candidates: @rejected.uniq, observed_access: observed_access,
      port_investigations: ports[:investigations] }
  end

  def plan(id)
    call
    @plans[id]
  end

  def for_occurrence(id)
    call
    @occurrence_candidates[id]
  end

  private

  def occurrences
    @occurrences ||= @issue.occurrences.includes(:normalized_denial, :raw_event, :host_snapshot,
      host: { current_state_observation: :host_snapshot }).order(occurred_at: :desc, id: :desc).index_by(&:id)
  end

  def current_state(occurrence)
    return @current_states[occurrence.host_id] if @current_states.key?(occurrence.host_id)
    host = occurrence.host
    snapshot = host.current_snapshot
    selinux = host.selinux_state_for
    @current_states[occurrence.host_id] = { host_snapshot_id: snapshot&.id, policy_identity: selinux["policy_identity"],
      boot_id: snapshot&.details&.dig("boot_id"), selinux: selinux,
      configuration_current: host.current_configuration? }
  end

  def base(occurrence, finding, kind, resource)
    permissions = occurrence.normalized_denial.permissions.uniq.sort
    id = Digest::SHA256.hexdigest([@issue.id, occurrence.host_id, kind, resource, permissions].to_json)
    { id: id, kind: kind, finding_kind: finding[:kind], host_id: occurrence.host_id,
      issue_signature_id: occurrence.issue_signature_id, permissions: permissions,
      hostname: occurrence.host.hostname, mechanically_supported: true, intent_confirmation_required: true,
      status: "proposed", limitations: [] }
  end

  def finish(candidate, basis, semantic_basis, plan, semantics_version: PLAN_SEMANTICS_VERSION)
    basis = basis.merge(issue_signature_id: candidate[:issue_signature_id], permissions: candidate[:permissions])
    candidate[:evidence_basis] = basis
    candidate[:plan_semantics_version] = semantics_version
    candidate[:semantic_plan_basis] = semantic_basis.merge(
      kind: candidate[:kind], host_id: candidate[:host_id], scope_kind: candidate[:scope_kind], permissions: candidate[:permissions],
      plan_inputs: {
        preview_steps: plan[:preview_steps].map { |step| step.slice(:command, :persistence, :explanation) },
        apply_steps: plan[:apply_steps].map { |step| step.slice(:command, :persistence, :explanation) },
        rollback_steps: plan[:rollback_steps].map { |step| step.slice(:command, :persistence, :explanation) },
        rollback_description: plan[:rollback_description], persistence: plan[:persistence],
        expected_effect: candidate[:expected_effect], scope_warning: candidate[:scope_warning], limitations: candidate[:limitations]
      })
    if plan[:verification_steps]
      candidate[:semantic_plan_basis][:plan_inputs][:verification_steps] = plan[:verification_steps].map { |step| step.slice(:command, :persistence, :explanation) }
    end
    share_file_remedy(candidate)
    @occurrence_candidates[basis[:occurrence_id]] << candidate
    # Keep the first (newest) basis, not a later iteration over older occurrences.
    @plans[candidate[:id]] ||= plan.merge(candidate.slice(:id, :title, :explanation, :scope_kind, :scope_description,
      :scope_warning, :expected_effect, :limitations, :evidence_basis, :plan_semantics_version))
    candidate
  end

  def share_file_remedy(candidate)
    return unless @issue.target_class == "file" && candidate[:kind].in?(%w[restore_configured_label enable_boolean])
    return unless candidate[:permissions].present? && (candidate[:permissions] - %w[getattr open read map]).empty?

    occurrence = occurrences.fetch(candidate[:evidence_basis][:occurrence_id])
    denial = occurrence.normalized_denial
    paths = Array(denial.details.dig("target_evidence", "filesystem_paths")).uniq
    path = paths.first
    return unless paths.one? && path.is_a?(String) && path.start_with?("/") && !path.match?(/[\0\r\n]/) && Pathname.new(path).cleanpath.to_s == path
    return if denial.target_context.blank? || occurrence.raw_event.boot_id.blank?

    candidate[:semantic_plan_basis] = candidate[:semantic_plan_basis].except(:permissions).merge(
      observation_scope: { path: path, target_context: denial.target_context, boot_id: occurrence.raw_event.boot_id })
    candidate[:plan_semantics_version] = FILE_REMEDY_SEMANTICS_VERSION
    candidate[:id] = ResolutionPlanBasis.digest(issue_id: @issue.id, plan_semantics_version: candidate[:plan_semantics_version],
      semantic_plan_basis: candidate[:semantic_plan_basis])
    candidate[:supporting_observations] = [{ issue_signature_id: occurrence.issue_signature_id,
      permissions: denial.permissions.uniq.sort, occurrence_id: occurrence.id, occurrence_count: 1,
      enforcement_modes: [denial.details.fetch("enforcement_mode", "unknown")] }]
  end

  def label_configuration_digest(occurrence, state)
    @label_configuration_digests ||= {}
    @label_configuration_digests[occurrence.host_id] ||= begin
      # ponytail: shared fcontext inventory; path-specific precedence/substitution facts could narrow this later.
      policy = state[:selinux].fetch("policy", {})
      contexts = policy["file_contexts"]
      modules = policy["modules"]
      ResolutionPlanBasis.digest(
        configured_policy_type: state[:selinux]["configured_policy_type"], enabled: state[:selinux]["enabled"],
        policy_package: policy["package"], modules: modules.nil? ? nil : ResolutionPlanBasis.ordered_set(modules),
        file_contexts: contexts.nil? ? nil : ResolutionPlanBasis.ordered_set(contexts))
    end
  end

  def label_candidate(occurrence, finding)
    path = finding[:path]
    return unless path.to_s.start_with?("/") && !path.include?("\0") && finding[:file_type].in?(%w[file dir directory])
    return unless finding[:expected_context_resolver] == "matchpathcon" && finding[:expected_context].present?

    @latest_contexts ||= Array(@intelligence[:expected_context_observations]).group_by { |o| [o[:host_id], o["path"]] }
      .transform_values { |items| items.max_by { |o| o["observed_at"].to_s } }
    latest = @latest_contexts[[occurrence.host_id, path]]
    return if latest && (latest["status"] != "resolved" || latest["expected_context"] != finding[:expected_context])

    candidate = base(occurrence, finding, "restore_configured_label", path)
    state = current_state(occurrence)
    candidate.merge!(title: "Restore the host-configured label for this path",
      explanation: "The AVC recorded #{finding[:observed_type]}; a later host matchpathcon inspection resolved #{finding[:expected_type]} for the same event-evidenced path.",
      intent_prompt: "I confirm this object belongs at this path and should use the host's configured SELinux labeling.",
      scope_kind: "single_object", scope_description: "Only #{path} on #{occurrence.host.hostname}; no recursion, including for a directory.",
      scope_warning: "The path may now be missing or refer to a replaced object. Inspect it and its configured label before applying.",
      expected_effect: "restorecon restores the configured SELinux type for this object. This does not prove the denied permission becomes allowed.",
      limitations: ["Expected labeling was inspected after the AVC, not at AVC time.",
        "Current path existence, inode identity and local mapping continuity are not verified.",
        "Automatic rollback cannot be generated safely from current evidence."])
    candidate[:presentation] = "primary"
    candidate[:presentation_reason] = "A retained absolute path has a host-resolved configured-label mismatch; suitability still requires inspection."
    unless state[:configuration_current]
      candidate[:status] = "evidence_changed"
      candidate[:unavailable_reason] = "The latest host configuration observation is missing or stale; refresh it before reviewing a restoration plan."
    end
    if state[:selinux].dig("policy", "file_context_mappings_status").in?(%w[unknown partial unavailable])
      candidate[:status] = "evidence_changed"
      candidate[:unavailable_reason] = "The current file-context mapping inventory is unknown, partial or unavailable; configured-label continuity cannot be checked."
    end
    q = Shellwords.escape(path)
    basis = { version: VERSION, occurrence_id: occurrence.id, host_id: occurrence.host_id,
      checkpoint_id: occurrence.host_snapshot_id, checkpoint_observed_at: occurrence.raw_event.host_observed_at,
      observation_event_id: finding[:observation_event_id], expected_context_observed_at: finding[:expected_context_observed_at],
      path: path, file_type: finding[:file_type], observed_context: finding[:observed_context], expected_context: finding[:expected_context],
      historical_policy_identity: occurrence.policy_identity,
      current_host_state: state.except(:configuration_current, :selinux),
      current_configuration_digest: label_configuration_digest(occurrence, state) }
    semantic_basis = {
      boot_id: state[:boot_id], current_policy_identity: state[:policy_identity],
      path: path, object_class: finding[:target_class], file_type: finding[:file_type],
      observed_context: finding[:observed_context],
      expected_context: { context: finding[:expected_context], resolver: finding[:expected_context_resolver],
        object_class: finding[:target_class], file_type: finding[:file_type], status: "resolved",
        semantics_version: EXPECTED_CONTEXT_SEMANTICS_VERSION },
      current_configuration_digest: basis[:current_configuration_digest]
    }
    finish(candidate, basis, semantic_basis, {
      preview_steps: [step("Inspect object identity", "stat -- #{q}", "Stop if the object is missing, replaced, or not the intended object."),
        step("Inspect current configured label", "matchpathcon -- #{q}", "Confirm the configured type still matches #{finding[:expected_type]}."),
        step("Preview labeling change", "sudo restorecon -n -v -- #{q}", "No label change; review the proposed result.")],
      apply_steps: [step("Restore this object's configured label", "sudo restorecon -v -- #{q}", "Applies to this object only; no recursive scope.", "configured_label")],
      rollback_steps: [], rollback_description: "Automatic rollback cannot be generated safely from current evidence. The old AVC context does not establish the current object's identity.",
      persistence: "Changes the on-disk label using existing host configuration; adds no persistent file-context mapping."
    })
  end

  def boolean_candidates(occurrence, finding)
    state = current_state(occurrence)
    Array(finding[:conditional_rules]).filter_map do |rule|
      name = rule[:expression]
      unless name.to_s.match?(/\A[A-Za-z][A-Za-z0-9_]*\z/) && rule[:branch] == "True" && rule[:state] == "inactive"
        @rejected << { kind: "conditional_boolean", reason: "Complex or negative conditional paths require additional state-change reasoning." }
        next
      end
      original = Array(finding[:booleans]).find { |b| b["name"] == name && b["status"] == "observed" && b["current"] == false }
      next unless original

      candidate = base(occurrence, finding, "enable_boolean", name)
      current = Array(state[:selinux]["booleans"]).find { |b| b["name"] == name }
      identity = state[:policy_identity]
      # Reuse a current exact fact where available; queue through the existing architecture otherwise.
      key = [identity, finding[:permission]]
      fact = @facts.fetch(key) do
        @facts[key] = PolicyFact.find_by(policy_identity: identity, query_kind: PolicyFact::QUERY_KIND,
          source_type: @issue.source_type, target_type: @issue.target_type, object_class: @issue.target_class, permission: finding[:permission])
      end
      current_rules = fact&.status == "matched" ? fact.matching_rules.select { |r| r[/\[\s*([^\]]+)\s*\]:True\z/, 1]&.strip == name } : []
      if current_rules.empty?
        unless @requested_current_facts || (fact && fact.status.in?(%w[matched no_match]))
          RequestResolutionPolicyFactsJob.perform_later(issue_id: @issue.id)
          @requested_current_facts = true
        end
        candidate[:status] = "no_longer_supported"
        candidate[:unavailable_reason] = "The latest policy fact is #{fact&.status || 'missing'} and supplies no matching positive conditional path; wait for or refresh policy evaluation."
      elsif current&.dig("status") != "observed" || !current["current"].in?([true, false]) || !state[:configuration_current]
        candidate[:status] = "evidence_changed"
        candidate[:unavailable_reason] = !state[:configuration_current] ? "The latest host configuration observation is missing or stale; check current state and refresh evidence before review." : "The latest Boolean value is not observed; obtain runtime state before reviewing a change."
      elsif current["current"] != false
        candidate[:status] = "no_longer_supported"
        candidate[:unavailable_reason] = "The latest retained Boolean value is already On; check current runtime state and retry the intended workload before considering another change."
      end
      candidate[:latest_observed_at] = occurrence.host.current_state_observation&.last_observed_at
      direct_source = Array(finding[:conditional_rules]).any? do |path|
        path[:expression] == name && PolicyRuleEvaluator::RULE.match(path[:rule].to_s)&.[](1) == @issue.source_type
      end
      candidate[:presentation] = direct_source ? "primary" : "technical_alternative"
      candidate[:presentation_reason] = direct_source ? "The retained conditional rule names the workload's source type directly. This is a review lead, not proof of intent." : "The retained rule matches through a source attribute, not a workload-specific source type. Confirm the capability's purpose before choosing this technical alternative."
      home_content = @issue.source_type == "httpd_t" && @issue.target_type == "user_home_t" && @issue.target_class == "file"
      if home_content
        paths = Array(occurrence.normalized_denial.details.dig("target_evidence", "filesystem_paths")).uniq
        candidate[:requires_home_content_review] = true
        candidate[:home_content_path] = paths.one? ? paths.first : nil
        candidate[:presentation] = "technical_alternative"
        candidate[:presentation_reason] = "Identify the file and inspect current/configured labels first. A matching Boolean does not establish intentional home-content access."
      end
      rules = (current_rules.presence || [rule[:rule]]).uniq.sort
      symbols = rules.filter_map do |r|
        match = PolicyRuleEvaluator::RULE.match(r)
        "#{match[1]} → #{match[2]}:#{match[3]}" if match
      end.uniq.join("; ")
      candidate.merge!(title: "Enable the SELinux capability controlled by #{name}",
        explanation: "An exact evaluated allow path provides #{@issue.source_type} → #{@issue.target_type}:#{@issue.target_class} #{finding[:permission]} when #{name} is On. The associated denial checkpoint recorded it Off.",
        intent_prompt: "I intend this workload to have the capability controlled by #{name}, including its broader host-wide policy effects.",
        scope_kind: "host_boolean", scope_description: "Host-wide boolean #{name} on #{occurrence.host.hostname}; not restricted to this process or destination.",
        scope_warning: "Retained rule scope: #{symbols}. Type/attribute membership applies beyond this occurrence. This boolean can activate other rules not enumerated by this tuple-specific fact; it does not just allow one port.",
        expected_effect: "Activates the retained True-branch allow path for #{finding[:permission]}. Other checks may still deny access; workload intent remains your decision.",
        limitations: ["Checkpoint state is not an AVC-time or apply-time measurement.", "Persistent rollback state unknown; runtime Off does not establish the persistent setting.",
          "The complete host-wide effects of this boolean are not enumerated.",
           (candidate[:status] == "no_longer_supported" ? "The latest retained state already has the boolean On or lacks a matching current policy fact; no applicable plan is exposed." : "Inspect current runtime and persistent state before making a change.")])
      if home_content
        candidate[:intent_prompt] = "I identified this file on the named host, checked its current and configured SELinux labels and account/home configuration, and confirm Apache should intentionally serve this home content. I reviewed this Boolean's broader host-wide effects."
      end
      basis = { version: VERSION, occurrence_id: occurrence.id, host_id: occurrence.host_id, finding_kind: finding[:kind],
        historical_policy_identity: finding[:policy_identity], checkpoint_id: occurrence.host_snapshot_id,
        historical_policy_fact_ids: Array(finding[:evaluations]).map { |f| f["policy_fact_id"] }.compact,
        checkpoint_observed_at: finding[:checkpoint_observed_at], boolean: name, checkpoint_value: false,
        current_policy_identity: identity, policy_fact_id: fact&.id, policy_fact_result: fact&.status,
        evaluator_version: fact&.evaluator_version, matching_rules: rules, current_boolean: current,
        current_host_state: state.except(:configuration_current, :selinux),
        source_type: @issue.source_type, target_type: @issue.target_type, object_class: @issue.target_class, permission: finding[:permission] }
      details = Array(fact&.rule_details).select do |detail|
        if detail["rule"].present?
          rules.include?(detail["rule"])
        else
          detail["conditional_expression"].to_s.strip == name && detail["conditional_branch"] == "True"
        end
      end.map { |detail| detail.merge("permissions" => Array(detail["permissions"]).uniq.sort) }
      semantic_basis = {
        boot_id: state[:boot_id], boolean: name, current_boolean: current&.slice("status", "current"),
        condition: { expression: name, branch: "True" },
        policy_support: { policy_identity: identity, policy_fact_id: fact&.id, query_kind: fact&.query_kind,
          source_type: @issue.source_type, target_type: @issue.target_type, object_class: @issue.target_class,
          permission: finding[:permission], result: fact&.status, evaluator_version: fact&.evaluator_version,
          matching_rules: rules, rule_details: ResolutionPlanBasis.ordered_set(details) }
      }
      if home_content
        basis[:home_content_names] = Array(occurrence.normalized_denial.details.dig("target_evidence", "object_names"))
        basis[:home_content_path] = candidate[:home_content_path]
        semantic_basis[:home_content_review_required] = true
        semantic_basis[:home_content_path] = candidate[:home_content_path]
        semantic_basis[:home_content_names] = (basis[:home_content_names].presence || [candidate[:home_content_path]].compact.map { |path| File.basename(path) }).sort
      end
      finish(candidate, basis, semantic_basis, {
        preview_steps: [step("Inspect runtime boolean", "getsebool #{name}", "Stop and re-review if runtime state is no longer Off."),
          step("Inspect persistent/local boolean configuration", "sudo semanage boolean -l", "Record the previous persistent setting before choosing a persistent change; this is inspection, not a preview of all policy effects.")],
        apply_steps: [step("Apply temporarily", "sudo setsebool #{name} on", "Runtime-only change; does not set the persistent value.", "temporary"),
          step("Apply persistently (optional)", "sudo setsebool -P #{name} on", "Explicit alternative: changes runtime and persistent configuration. First record persistent state; no automatic persistent rollback is available.", "persistent")],
        rollback_steps: [step("Undo the temporary runtime change", "sudo setsebool #{name} off", "Only if the original runtime state is still Off before applying; does not undo a persistent change.", "temporary")],
        rollback_description: "Persistent rollback state unknown. No persistent rollback command can be generated from the retained runtime value.",
        persistence: "Temporary is the default plan option. Persistent is a separate optional operation, never required together with temporary."
      })
    end
  end

  def step(title, command, explanation, persistence = "inspection")
    { title: title, command: command, explanation: explanation, persistence: persistence }
  end

  def observed_access
    occurrence = occurrences.values.first
    return nil unless occurrence
    denial = occurrence.normalized_denial
    paths = Array(denial.details.dig("target_evidence", "filesystem_paths"))
    ports = if denial.permissions.include?("name_bind")
      Array(denial.details.dig("network_evidence", "bind_port_fields"))
        .map(&:to_s).select { |value| value.match?(/\A\d+\z/) && value.to_i.between?(0, 65_535) }.uniq
    else
      IssueIntelligence.destination_ports(denial.details)
    end
    resource = paths.one? ? paths.first : %w[tcp_socket udp_socket].include?(denial.target_class) && ports.one? ? "#{denial.target_class == 'udp_socket' ? 'UDP' : 'TCP'}/#{ports.first}" : "Resource identity not established"
    { occurrence_id: occurrence.id, host_id: occurrence.host_id, hostname: occurrence.host.hostname,
      actor: denial.command.presence || denial.source_type, source_type: denial.source_type, resource: resource,
      target_type: denial.target_type, object_class: denial.target_class, permissions: denial.permissions,
      operation_label: denial.permissions.map { |p| { "name_connect" => "connect", "name_bind" => "bind", "entrypoint" => "start (entrypoint)" }.fetch(p, p) }.join(", "),
      outcome: "DENIED", observed_at: occurrence.occurred_at }
  end
end
