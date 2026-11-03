class PrometheusMetricsExporter
  def call(result)
    lines = []
    family(lines, "issues", "Registered issues by persisted status and disposition.")
    Issue::STATUSES.product(Issue::DISPOSITIONS + ["mixed"]).each do |status, disposition|
      sample(lines, "issues", result.issues.fetch([status, disposition], 0), status: status, disposition: disposition)
    end
    scalar(lines, "regressed_issues", "Currently regressed issues; a subset of open issues.", result.regressed_issues)
    scalar(lines, "occurrences", "Current retained occurrences, excluding superseded interpretations.", result.occurrences)
    scalar(lines, "ungrouped_occurrences", "Current occurrences without an associated issue.", result.ungrouped_occurrences)
    scalar(lines, "hosts", "Registered hosts, regardless of reporting freshness.", result.hosts)
    family(lines, "hosts_by_selinux_enforcement", "Registered hosts by fresh, trusted host-wide SELinux enforcement evidence.")
    DomainMetricsQuery::ENFORCEMENT_STATES.each do |state|
      sample(lines, "hosts_by_selinux_enforcement", result.hosts_by_selinux_enforcement.fetch(state, 0), state: state)
    end
    scalar(lines, "hosts_with_open_issues", "Distinct hosts with current occurrences associated with open issues.", result.hosts_with_open_issues)
    family(lines, "agent_installations", "Agent installations by recent contact; not collection or delivery health.")
    AgentInstallation::REPORTING_STATES.each do |state|
      sample(lines, "agent_installations", result.agent_installations.fetch(state, 0), state: state)
    end
    lines.join("\n") + "\n"
  end

  private

  def family(lines, name, help)
    lines << "# HELP secentral_#{name} #{help}"
    lines << "# TYPE secentral_#{name} gauge"
  end

  def scalar(lines, name, help, value)
    family(lines, name, help)
    sample(lines, name, value)
  end

  def sample(lines, name, value, **labels)
    suffix = labels.empty? ? "" : "{#{labels.map { |key, label| %(#{key}="#{escape(label)}") }.join(',')}}"
    lines << "secentral_#{name}#{suffix} #{value}"
  end

  def escape(value)
    value.to_s.gsub(/[\\"\n]/) { |character| { "\\" => "\\\\", '"' => '\\"', "\n" => '\\n' }.fetch(character) }
  end
end
