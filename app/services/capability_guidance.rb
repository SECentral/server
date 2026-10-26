class CapabilityGuidance
  CLASSES = %w[capability capability2 cap_userns cap2_userns].freeze

  def self.call(occurrence)
    denial = occurrence.normalized_denial
    return unless CLASSES.include?(denial.target_class)

    explanation = "Linux capabilities are individual administrator privileges checked when a program performs a protected operation."
    if denial.permissions.include?("net_admin")
      explanation += " net_admin covers network administration, including interface/routing changes and privileged socket settings."
    elsif denial.permissions.include?("mac_admin")
      explanation += " mac_admin is checked for some security-label administration operations."
    end
    result = { explanation: explanation }
    raw = occurrence.raw_event
    return result unless raw

    # Decode only an unambiguous x86-64 socket-buffer request from this event.
    normalizer = AvcNormalizer.new(raw.raw_audit_records.to_a)
    avcs = normalizer.call
    syscalls = normalizer.syscall_records
    return result unless avcs.one? && avcs.sole[:status] == "ok" && syscalls.one?

    avc = avcs.sole
    syscall = syscalls.sole
    pids = avc[:evidence_provenance].select { |item| item["kind"] == "pid" && item["source_record_type"] == "AVC" }.map { |item| item["value"] }
    return result unless avc[:source_context] == denial.source_context && avc[:target_class] == denial.target_class && avc[:permissions] == denial.permissions &&
      pids == [syscall["pid"]] && syscall["subj"] == denial.source_context && syscall["exe"] == denial.executable

    outcome = NormalizedDenial.syscall_outcome("syscall_evidence" => syscalls)
    if denial.enforcement_mode == "permissive" && outcome == "succeeded"
      result[:outcome] = "This AVC was non-enforced (permissive=1). The associated system call succeeded; application outcome is not established."
    elsif outcome == "failed"
      result[:outcome] = "The associated system call failed."
    end
    errors = normalizer.selinux_error_records
    if denial.permissions.include?("mac_admin") && errors.one? && errors.sole["op"] == "setxattr" && errors.sole["invalid_context"].present?
      result[:evidence] = "The same audit event reports an invalid SELinux context: #{errors.sole['invalid_context']}. A security context is the SELinux label assigned to a process or file."
      result[:inspection] = "Find the target path in the recorded command line, then compare the requested context with the host's loaded policy and inspect the object's current label."
      result[:verification] = "If you correct the requested context, verify the intended labeling operation and the resulting label."
      return result
    end
    return result unless denial.permissions.include?("net_admin") && syscall["arch"] == "c000003e" && syscall["syscall"] == "54"

    level, option = syscall.values_at("a1", "a2").map { |value| Integer(value, 16) if value.to_s.match?(/\A[0-9a-f]+\z/i) }
    return result unless level == 1 && [32, 33].include?(option)

    name, direction = option == 32 ? ["SO_SNDBUFFORCE", "send"] : ["SO_RCVBUFFORCE", "receive"]
    result[:evidence] = "The recorded x86-64 setsockopt call selected #{name}: setting the socket #{direction} buffer (memory for #{option == 32 ? 'outgoing' : 'incoming'} data) with permission to exceed the normal size limit."
    result[:hypothesis] = "The service or a loaded module may be tuning socket buffers."
    result[:inspection] = "Review the service's startup configuration and modules for forced #{direction}-buffer settings."
    result[:verification] = "After reviewing the socket-buffer setting, retry the intended request and check the application response under the intended SELinux enforcement mode."
    result
  end
end
