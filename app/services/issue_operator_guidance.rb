require "pathname"
require "shellwords"

class IssueOperatorGuidance
  def self.call(issue, diagnosis: nil, triage_guidance: nil, occurrence: nil)
    new(issue, diagnosis, triage_guidance, occurrence).call
  end

  def initialize(issue, diagnosis, triage_guidance, occurrence = nil)
    @issue, @diagnosis, @triage, @occurrence = issue, diagnosis, triage_guidance, occurrence
  end

  def call
    occurrences = @issue.occurrences.includes(:host, :normalized_denial).order(occurred_at: :desc, id: :desc).to_a
    occurrence = if @occurrence
      @occurrence
    elsif @diagnosis
      occurrences.find { |item| item.id == @diagnosis[:occurrence_id] }
    elsif @triage
      occurrences.find { |item| paths(item).include?(@triage[:path]) }
    else
      occurrences.first
    end
    return unless occurrence

    denial = occurrence.normalized_denial
    retained_paths = paths(occurrence)
    path = @diagnosis&.dig(:path) || @triage&.dig(:path) || (retained_paths.first if retained_paths.one?)
    path = nil unless retained_paths.include?(path) && valid_path?(path)
    permissions = Array(denial.permissions)
    checks = []
    if path && %w[file dir lnk_file fifo_file chr_file blk_file sock_file].include?(denial.target_class)
      q = Shellwords.escape(path)
      checks << check("Current object label", "ls -ldZ -- #{q}", "Read the current object's context; stop if the path is missing or refers to a different object.")
      checks << check("Host-configured context", "matchpathcon -- #{q}", "The third colon-separated context field is the type. Compare this configured type with the current object label, not just the historical AVC label.")
      checks << check("Read-only restoration preview", "restorecon -n -v -- #{q}", "Shows a proposed label change without applying it. If current and configured types agree, restoration may do nothing. If lookup fails or the configured label is unsuitable, investigate configuration instead.")
      if @diagnosis&.dig(:kind) == "no_matching_allow"
        checks << check("Local file-context customizations", "semanage fcontext -l -C", "Compare local mappings with the workload's effective data path and intended file role.")
      end
    end
    # Bind investigation starts with listener ownership and classification, not a matching Boolean.
    boolean_checks = []
    conditions = Array(@diagnosis&.dig(:condition_boolean_states))
    conditions.sort_by { |condition| condition[:rule].to_s.start_with?("allow #{denial.source_type} ") ? 0 : 1 }.each do |condition|
      Array(condition[:booleans]).each do |item|
        name = item["name"] || item[:name]
        next unless name.to_s.match?(/\A[A-Za-z][A-Za-z0-9_]*\z/)

        boolean_checks << check("Current Boolean: #{name}", "getsebool #{name}", "Check the current runtime state on this host before retrying the intended workload.")
      end
    end
    boolean_checks.uniq! { |item| item[:command] }
    checks.concat(boolean_checks) unless permissions.include?("name_bind")
    port_checks = PortInspectionGuidance.call(denial)
    if port_checks.any?
      checks.concat(port_checks.map { |item| check(item[:reason], InvestigationCommandRenderer.call(item), item[:expected]) })
    elsif %w[tcp_socket udp_socket].include?(denial.target_class)
      checks << check("Current listeners", denial.target_class == "udp_socket" ? "ss -lunp" : "ss -ltnp", "Compare the listening address, port and process owner with the intended service.") if permissions.include?("name_bind")
      checks << check("Configured port classifications", "semanage port -l", "Find the observed protocol/port within individual entries or ranges and compare its type with the recorded AVC label.")
      checks << check("Local port customizations", "semanage port -l -C", "Review local overrides before considering any manual configuration change.")
      endpoint = PortMappingGuidance.endpoint(denial)
      if endpoint && denial.source_type.to_s.match?(/\A[A-Za-z][A-Za-z0-9_]*\z/)
        checks << check("Current local policy alternatives", InvestigationCommandRenderer.call(kind: :port_policy_alternatives, source_type: denial.source_type, object_class: denial.target_class, operation: endpoint[:operation]),
          "Inspect matching target types, attributes and conditions in the host's currently loaded policy.")
      end
    end
    checks.concat(boolean_checks) if permissions.include?("name_bind")
    manual, possible_fix, verification = next_steps(denial, permissions, path)
    {
      source: { occurrence_id: occurrence.id, host_id: occurrence.host_id, hostname: occurrence.host.hostname,
        occurred_at: occurrence.occurred_at, path: path, observed_type: denial.target_type, object_class: denial.target_class }.merge(PortMappingGuidance.endpoint(denial) || {}),
      checks: checks, manual_check: manual, possible_fix: possible_fix, verification: verification,
      verification_limit: "Record the test time and check fresh AVCs, enforcement/domain permissiveness and event-delivery health alongside the workload result.",
      restriction: "Keep unwanted access denied and correct the calling workload or exposure. Verify legitimate work still succeeds and record your decision in a note."
    }
  end

  private

  def paths(occurrence)
    Array(occurrence.normalized_denial.details.dig("target_evidence", "filesystem_paths"))
  end

  def valid_path?(path)
    path.is_a?(String) && path.start_with?("/") && !path.match?(/[\0\r\n]/) && Pathname.new(path).cleanpath.to_s == path
  end

  def check(title, command, interpretation)
    { title: title, command: command, interpretation: interpretation }
  end

  def next_steps(denial, permissions, path)
    object_class = denial.target_class
    if permissions.include?("name_bind")
      ["Confirm the service's intended listener and inspect its actual configuration.",
       "Compare correcting unintended Listen configuration, using an appropriate existing endpoint, reviewing a relevant Boolean, or classifying a required nonstandard port. Mapping options require exact policy support and complete effective/local range evidence.",
       "After an approved configuration validation and reload/restart, check the intended listener address/port and application response. Check that no unintended interface is exposed; account for service interruption."]
    elsif permissions.include?("name_connect")
      ["Confirm the backend address, port and service in workload configuration. Test through the confined workload.",
       "Check the relevant Boolean's current runtime state and retry the intended workload first if the capability is already observed On. Otherwise compare correcting an unintended destination, using an appropriate existing endpoint, reviewing a relevant Boolean or an evidence-backed port classification. Port mappings affect other workloads using the same host/protocol/port.",
       "Retry the same application or proxy request through the affected workload and verify the intended backend response."]
    elsif (permissions & %w[execute entrypoint execute_no_trans transition]).any?
      ["Confirm the intended launch, executable identity and requested execution context.",
       "If this executable belongs here, inspect its current and configured labels before reviewing targeted restoration. Confirm execution is intended before reviewing any broader capability change; otherwise correct the calling workload.",
       "Retry only the intended launch and verify its expected status and output. If resulting-domain behavior matters, inspect the actual child process context separately. For a confirmed CGI workload, retry its actual request."]
    elsif %w[file dir lnk_file fifo_file chr_file blk_file sock_file].include?(object_class)
      fix = if !path && denial.source_type == "httpd_t" && denial.target_type == "user_home_t" && (permissions & %w[read open]).any?
        "Identify the object and decide whether serving home-directory content is intentional. Once the path is known, inspect its current label (ls -ldZ), configured context (matchpathcon), and read-only restoration preview (restorecon -n -v) on the selected host. Restore only if current labeling differs from suitable configured labeling; do not relabel intentional home content merely to allow access. If serving home content is intended, compare the home-content Boolean's broader host-wide read access with workload configuration changes. If website content was misplaced or exposed accidentally, investigate deployment paths and web configuration instead of broadening access. No path-specific restoration command is supported without a retained absolute path."
      elsif !path
        "Identify the object and its intended use before choosing a labeling or policy change. No path-specific restoration is supported without a retained absolute path."
      else
        "Use the inspection results to decide whether configured labeling suits the object's intended role. If labels already agree, investigate workload paths and local mappings rather than restoring the same label."
      end
      verification = if denial.source_type == "mysqld_t"
        "Confirm the effective data path and application readiness; use a read-only query against known existing data. Do not initialize or overwrite data."
      else
        "Repeat the intended file access through the affected workload and check expected output. For confirmed web content, retry the actual request and verify its status and content."
      end
      [path ? "Confirm the file's role and the workload's effective configured path." : "Identify the complete absolute path and intended use from the host/workload configuration before path-specific checks. Do not reconstruct it from a basename.", fix, verification]
    else
      ["Review the exact denied operation and workload intent with the affected host's operator.",
       "Use a manual configuration/policy review if no supported reviewed option fits; keeping the restriction is a valid choice.",
       "Repeat the intended workload operation and confirm its actual result; review any new denials separately."]
    end
  end
end
