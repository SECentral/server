class CapabilityGuidance
  CLASSES = %w[capability capability2 cap_userns cap2_userns].freeze

  def self.call(occurrence)
    denial = occurrence.normalized_denial
    return unless CLASSES.include?(denial.target_class)

    explanation = "Linux capabilities are individual administrator privileges checked when a program performs a protected operation."
    if denial.permissions.include?("net_admin")
      explanation += " net_admin covers network administration, including interface/routing changes and privileged socket settings."
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

    details = denial.details
    if details["permissive"] == true && syscall["success"] == "yes"
      result[:outcome] = "SELinux logged this request without blocking it (permissive mode). The associated system call succeeded."
    elsif syscall["success"] == "no"
      result[:outcome] = "The associated system call failed."
    end
    return result unless denial.permissions.include?("net_admin") && syscall["arch"] == "c000003e" && syscall["syscall"] == "54"

    level, option = syscall.values_at("a1", "a2").map { |value| Integer(value, 16) if value.to_s.match?(/\A[0-9a-f]+\z/i) }
    return result unless level == 1 && [32, 33].include?(option)

    name, direction = option == 32 ? ["SO_SNDBUFFORCE", "send"] : ["SO_RCVBUFFORCE", "receive"]
    result[:evidence] = "The recorded x86-64 setsockopt call selected #{name}: setting the socket #{direction} buffer (memory for #{option == 32 ? 'outgoing' : 'incoming'} data) with permission to exceed the normal size limit."
    result[:hypothesis] = "The service or a loaded module may be tuning socket buffers. Check its startup configuration and modules for forced #{direction}-buffer settings."
    result
  end
end
