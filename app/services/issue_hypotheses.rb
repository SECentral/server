class IssueHypotheses
  def self.call(issue, intelligence: nil, triage: nil)
    new(issue, intelligence || IssueIntelligence.call(issue), triage || IssueTriageSignals.call(issue)).call
  end

  def initialize(issue, intelligence, triage)
    @issue = issue
    @intelligence = intelligence
    @triage = triage
  end

  def call
    hypotheses = [labeling_mismatch, file_context_difference, policy_version, custom_policy, application_behavior].compact
    hypotheses.presence || [insufficient_evidence]
  end

  private

  def policy_version
    signal = signal("policy_version_correlation")
    return unless signal

    hypothesis("policy_version_correlation", "Policy-version correlation", "medium", [
      evidence("Policy versions are distributed differently across hosts with and without this issue.", signal[:evidence], "issue_triage_signals")
    ], [], ["causal policy-change history"], "current_configuration_fleet", evidence_status: "possible_correlation", why: "The policy version is more common in the affected cohort.", does_not_prove: "The policy version caused the denial.", confirmation: "Compare a policy change event with the first denial.")
  end

  def file_context_difference
    with_occurrence = @intelligence[:fleet][:with_occurrence_file_contexts] || {}
    without_occurrence = @intelligence[:fleet][:without_occurrence_file_contexts] || {}
    affected_hosts = @intelligence[:fleet][:hosts_with_occurrence].to_i
    unaffected_hosts = @intelligence[:fleet][:hosts_without_occurrence].to_i
    return if affected_hosts.zero? || unaffected_hosts.zero?

    mapping = (with_occurrence.keys | without_occurrence.keys).find do |key|
      key[3] == "custom" && with_occurrence.fetch(key, 0) != without_occurrence.fetch(key, 0)
    end
    return unless mapping

    name, file_type, context, provenance = mapping
    hypothesis("local_file_context_difference", "Local file-context difference", "low", [
      evidence("Local file-context rule #{name} (#{file_type}) maps to #{context} on #{with_occurrence.fetch(mapping, 0)}/#{affected_hosts} hosts with an occurrence and #{without_occurrence.fetch(mapping, 0)}/#{unaffected_hosts} without one.", { pattern: name, file_type: file_type, context: context, provenance: provenance, with_occurrence: with_occurrence.fetch(mapping, 0), without_occurrence: without_occurrence.fetch(mapping, 0), affected_hosts: affected_hosts, unaffected_hosts: unaffected_hosts }, "issue_intelligence")
    ], [], ["mapping change history", "policy review by an operator"], "current_configuration_fleet", evidence_status: "possible_correlation", why: "A custom file-context mapping differs between affected and unaffected cohorts.", does_not_prove: "The mapping caused this denial or was present at denial time.", confirmation: "Review the mapping change and the label state at the denial timestamp.")
  end

  def labeling_mismatch
    current = @intelligence[:correlated_file_contexts].to_a.select { |item| item["status"] == "observed" && item["expected_status"] == "observed" }
    candidates = current.filter_map do |item|
      actual = context_type(item["context"])
      expected = context_type(item["expected_context"])
      next unless actual.present? && expected.present? && actual != expected
      { path: item["path"], actual: item["context"], expected: item["expected_context"] }
    end.uniq { |item| [item[:path], context_type(item[:actual]), context_type(item[:expected])] }
    candidate = candidates.one? ? candidates.first : nil
    return unless candidate

    hypothesis("labeling_mismatch", "Event-associated label differs from policy expectation", "low", [
      evidence("Event-associated label for #{candidate[:path]} was #{candidate[:actual]}, while the recorded policy expectation was #{candidate[:expected]}.", candidate, "issue_intelligence")
    ], [], ["label state at denial time", "current label state"], "correlated_occurrence_state", evidence_status: "strong_lead", why: "The label collected with the event conflicts with its recorded policy expectation.", does_not_prove: "That the same mismatch existed at AVC time or remains current.", confirmation: "Find a label snapshot close to the AVC or confirm the file was relabeled.")
  end

  def custom_policy
    with_occurrence = @intelligence[:fleet][:with_occurrence_modules] || {}
    without_occurrence = @intelligence[:fleet][:without_occurrence_modules] || {}
    return if @intelligence[:fleet][:hosts_with_occurrence].to_i.zero? || @intelligence[:fleet][:hosts_without_occurrence].to_i.zero?
    module_info = (with_occurrence.keys | without_occurrence.keys).find do |key|
      next false unless key[2] == "custom"
      with_occurrence.fetch(key, 0) != without_occurrence.fetch(key, 0)
    end
    return unless module_info

    name, priority, provenance = module_info
    hypothesis("custom_policy_difference", "Custom-policy difference", "low", [
      evidence("Custom module #{name} at priority #{priority} is present on #{with_occurrence.fetch(module_info, 0)}/#{@intelligence[:fleet][:hosts_with_occurrence]} hosts with an occurrence and #{without_occurrence.fetch(module_info, 0)}/#{@intelligence[:fleet][:hosts_without_occurrence]} without one.", { module: name, priority: priority, provenance: provenance, with_occurrence: with_occurrence.fetch(module_info, 0), without_occurrence: without_occurrence.fetch(module_info, 0), affected_hosts: @intelligence[:fleet][:hosts_with_occurrence], unaffected_hosts: @intelligence[:fleet][:hosts_without_occurrence] }, "issue_intelligence")
    ], [], ["module change history", "policy review by an operator"], "current_configuration_fleet", evidence_status: "possible_correlation", why: "A custom module is distributed differently between affected and unaffected cohorts.", does_not_prove: "That the module contains a rule relevant to this denial.", confirmation: "Evaluate the loaded policy and review module change history.")
  end

  def application_behavior
    signals = @triage[:signals].select { |item| %w[host_concentration frequency_increase new_issue new_host_issue].include?(item[:code]) }
    process = @intelligence[:process_evidence]
    return if signals.empty? || process.values.all?(&:empty?)

    signal_text = signals.map { |item| item[:explanation].presence || item[:code].to_s.humanize }.join(" ")
    processes = (process["executables"] + process["commands"]).uniq.join(", ")
    fact = "Process evidence (#{processes}) was recorded for this issue. #{signal_text}"
    hypothesis("application_behavior_change", "Process-associated occurrence pattern", "low", [
      evidence(fact, { process_evidence: process, signals: signals.map { |item| item[:code] } }, "issue_intelligence_and_triage_signals")
    ], [], ["application deployment history", "operator confirmation of expected behavior"], "recent_and_baseline_occurrences", evidence_status: "possible_correlation", why: "Recent occurrences are associated with a process and concentrated in time or hosts.", does_not_prove: "That the process changed or caused the denial.", confirmation: "Compare process deployment history with the first denial.")
  end

  def insufficient_evidence
    hypothesis("insufficient_evidence", "Insufficient evidence", "low", [], [], ["a stronger hypothesis with required supporting evidence"], "retained_issue_evidence", evidence_status: "not_evaluated", why: "Retained evidence does not support a specific lead.", does_not_prove: "That the issue is harmless.", confirmation: "Collect the missing host, policy, or temporal evidence.")
  end

  def signal(code)
    @triage[:signals].find { |item| item[:code] == code }
  end

  def context_type(context)
    context.to_s.split(":", 4)[2]
  end

  def evidence(fact, basis, source)
    { fact: fact, basis: basis, source: source, certainty: "derived" }
  end

  def hypothesis(kind, label, confidence_band, supporting_evidence, contradicting_evidence, missing_evidence, temporal_scope, evidence_status:, why:, does_not_prove:, confirmation:)
    { kind: kind, label: label, confidence_band: confidence_band, supporting_evidence: supporting_evidence,
      contradicting_evidence: contradicting_evidence, missing_evidence: missing_evidence,
      temporal_scope: temporal_scope, evidence_status: evidence_status, why: why,
      does_not_prove: does_not_prove, confirmation: confirmation, checks: [] }
  end
end
