class SelinuxAdministrativeEvent
  def self.supported(relation)
    relation.where(category: "selinux_administrative")
      .where("transition_type IN (?) OR boolean_changes <> '[]'::jsonb OR EXISTS (SELECT 1 FROM raw_audit_records WHERE raw_event_id = raw_events.id AND record_type IN (1403, 1404, 2312))", RawEvent::STATE_TRANSITIONS)
  end

  def self.facts(event)
    changes = event.boolean_changes.map do |change|
      { name: change["name"], old_value: change["old_value"] == 1, new_value: change["new_value"] == 1,
        state_change_established: change["success"] && change["old_value"] != change["new_value"] }
    end
    type = event.transition_type || (event.raw_audit_records.any? { |record| record.record_type == 2312 && RawEvent.file_context_record?(record.payload) } ? "file_context_change" : event.raw_audit_records.any? { |record| record.record_type == 2312 } ? "port_change" : event.raw_audit_records.any? { |record| record.record_type == 1404 } ? "enforcement_change" : changes.any? ? "boolean_change" : "policy_load")
    {
      transition_type: type, boundary_established: RawEvent::STATE_TRANSITIONS.include?(event.transition_type),
      boolean_changes: changes,
      enforcement_changes: event.enforcement_changes.map do |change|
        { old_mode: change["old_mode"], new_mode: change["new_mode"],
          state_change_established: change["success"] && change["old_mode"] != change["new_mode"] }
      end,
      port_changes: event.port_changes.map { |change| change.merge("boundary_established" => change["success"]) },
      file_context_changes: event.file_context_changes.map { |change| change.merge("boundary_established" => change["success"], "state_change_established" => false) }
    }
  end

  def self.actor(records)
    fields = Hash.new { |hash, key| hash[key] = [] }
    records.select { |record| [1403, 1404, 1405, 2312, 1300, 1327].include?(record.record_type) }.each do |record|
      record.payload.scan(/(?:\A|\s)(auid|uid|pid|ses|subj|exe|comm|proctitle)=("(?:\\.|[^"])*"|\S+)/).each do |key, value|
        decoded = if value.start_with?('"')
          value[1...-1].gsub('\\"', '"').gsub("\\\\", "\\")
        elsif %w[exe comm proctitle].include?(key) && value.match?(/\A(?:[0-9A-Fa-f]{2})+\z/)
          [value].pack("H*").force_encoding("UTF-8").scrub.tr("\0", " ")
        else
          value
        end
        fields[key] << decoded
      end
    end
    values = fields.transform_values { |items| items.uniq.one? ? items.first : nil }
    { login_uid: audit_id(values["auid"]), execution_uid: audit_id(values["uid"]), pid: audit_id(values["pid"]), context: values["subj"], session: audit_id(values["ses"]),
      executable: values["exe"], command: values["comm"], proctitle: values["proctitle"] }
  end

  def self.audit_id(value)
    value.to_i if value.to_s.match?(/\A\d+\z/) && value != "4294967295"
  end
  private_class_method :audit_id
end
