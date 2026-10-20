class IssueActivityGroups
  WINDOW = 0.1.seconds

  def self.call(occurrences)
    new(occurrences).call
  end

  def initialize(occurrences)
    @occurrences = occurrences.to_a
  end

  def call
    # ponytail: page-local correlation; add an activity index if cross-page groups become necessary.
    events = @occurrences.group_by(&:raw_event_id).values.select(&:one?).map(&:first)
    by_serial = events.group_by { |item| [item.host_id, item.raw_event.boot_id, item.raw_event.audit_sequence] }
    pairs = {}
    events.each do |item|
      next unless item.normalized_denial.permissions.sort == ["map"]

      previous = by_serial[[item.host_id, item.raw_event.boot_id, item.raw_event.audit_sequence - 1]]
      next unless previous&.one? && related?(previous.first, item)

      pairs[item.id] = [previous.first, item]
    end
    consumed = pairs.values.flatten.map(&:id)
    @occurrences.filter_map do |item|
      members = pairs[item.id]
      next if !members && consumed.include?(item.id)

      members ||= [item]
      { occurrence_ids: members.map(&:id), correlated: members.size > 1,
        basis: members.size > 1 ? "Same host, boot, PID, device/inode and contexts; consecutive open/read then map audit events within 100ms. This is correlation, not proof of one request or read-only mapping." : nil }
    end
  end

  private

  def related?(first, second)
    return false if first.raw_event.boot_id.blank? || second.raw_event.boot_id.blank?

    denials = [first.normalized_denial, second.normalized_denial]
    permissions = denials.first.permissions
    return false unless (permissions - %w[getattr open read]).empty? && (permissions & %w[open read]).sort == %w[open read]
    return false unless denials.all? { |denial| denial.target_class == "file" && denial.details["enforcement_mode"] == "permissive" }
    elapsed = second.occurred_at - first.occurred_at
    return false unless elapsed.between?(0, WINDOW)
    return false if denials.any? { |denial| Array(denial.details["syscall_evidence"]).any? { |syscall| %w[no false 0].include?(syscall["success"].to_s) } }

    identities = [first, second].map { |item| AvcNormalizer.new(item.raw_event.raw_audit_records.to_a).activity_identity }
    return false unless identities.first && identities.first == identities.last
    return false if %i[command executable].any? { |field| denials.filter_map { |denial| denial.public_send(field).presence }.uniq.size > 1 }

    paths = denials.map { |denial| Array(denial.details.dig("target_evidence", "filesystem_paths")).uniq }
    return false if paths.any? { |items| items.size > 1 }
    return false if paths.all?(&:present?) && paths.first != paths.last

    names = denials.flat_map { |denial| Array(denial.details.dig("target_evidence", "object_names")) }.map { |name| File.basename(name) }
    names.concat(paths.flatten.map { |path| File.basename(path) }).uniq.size <= 1
  end
end
