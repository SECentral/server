class PolicyDraftWorkspace
  def self.stage!(draft, issue, occurrence)
    raise ArgumentError, "Issue and draft must belong to the same organization" unless draft.organization_id == issue.organization_id

    denial = occurrence.normalized_denial
    intelligence = IssueIntelligence.call(issue)
    analyzer = IssueDiagnosis.new(issue, intelligence)
    alternatives = ResolutionCandidates.new(issue, intelligence: intelligence, analyzer: analyzer).for_occurrence(occurrence.id)
      .map { |candidate| candidate.slice(:kind, :title, :status) }
    findings = analyzer.per_host.flat_map { |h| h[:occurrence_diagnoses] }.find { |o| o[:occurrence_id] == occurrence.id }
    provenance = { issue_id: issue.id, issue_signature_id: occurrence.issue_signature_id, occurrence_id: occurrence.id, host_id: occurrence.host_id,
      occurred_at: occurrence.occurred_at.iso8601(6), policy_identity: occurrence.policy_identity,
      resources: Array(denial.details.dig("target_evidence", "filesystem_paths")),
      destination_ports: IssueIntelligence.destination_ports(denial.details), known_alternatives: alternatives,
      finding_kinds: Array(findings&.dig(:findings)).map { |f| f[:kind] },
      checkpoint_id: occurrence.host_snapshot_id, checkpoint_observed_at: occurrence.raw_event.host_observed_at,
      staging_note: "An identical staged tuple merges evidence references. Broader attribute-rule equivalence has not been evaluated." }
    provenance = JSON.parse(provenance.to_json)
    draft.with_lock do
      Array(denial.permissions).each do |permission|
        entry = draft.policy_draft_entries.find_or_initialize_by(source_type: denial.source_type,
          target_type: denial.target_type, object_class: denial.target_class, permission: permission)
        entry.provenance = (entry.provenance + [provenance]).uniq
        entry.save!
      end
      draft.update!(status: "draft")
    end
  end

  def self.serialize(draft)
    entries = draft.policy_draft_entries.order(:id).map do |entry|
      entry.attributes.slice("id", "source_type", "target_type", "object_class", "permission", "provenance").merge(
        "known_alternatives" => entry.provenance.flat_map { |p| Array(p["known_alternatives"]) }.uniq)
    end
    { id: draft.id, name: draft.name, organization_id: draft.organization_id, operator: draft.operator,
      status: draft.status, updated_at: draft.updated_at, entries: entries,
      evidence_version: Digest::SHA256.hexdigest(entries.to_json),
      limitations: ["Staged permissions are semantic evidence, not approved literal rules.",
        "No authoritative compilation or exact-policy module validation has been performed.",
        "A literal type allow applies beyond the recorded object, process and host."] }
  end

  def self.export(draft, format:, module_name:, literal_confirmed:, evidence_version:)
    draft.with_lock do
      payload = serialize(draft)
      if format == "te"
        raise ArgumentError, "Review and explicitly confirm literal type-wide rules before TE export" unless literal_confirmed == true
        raise ArgumentError, "Draft evidence changed; review the updated entries before export" unless evidence_version == payload[:evidence_version]
        raise ArgumentError, "Module name must be a SELinux identifier (maximum 64 characters)" unless module_name.to_s.match?(/\A[A-Za-z][A-Za-z0-9_]{0,63}\z/)
        entries = draft.policy_draft_entries.order(:id).to_a
        raise ArgumentError, "Cannot export an empty draft" if entries.empty?
        types = entries.flat_map { |e| [e.source_type, e.target_type] }.uniq.sort
        classes = entries.group_by(&:object_class).sort.map { |klass, rows| "  class #{klass} { #{rows.map(&:permission).uniq.sort.join(' ')} };" }
        rules = entries.map { |e| "allow #{e.source_type} #{e.target_type}:#{e.object_class} #{e.permission};" }
        source = ["# PROPOSED / UNVALIDATED: not proven to resolve any issue. Review type-wide scope and alternatives.",
          "module #{module_name} 1.0;", "require {", *types.map { |t| "  type #{t};" }, *classes, "}", *rules].join("\n") + "\n"
        payload = { filename: "#{module_name}.te", content: source, validation_status: "unvalidated",
          build_steps: ["checkmodule -M -m -o #{module_name}.mod #{module_name}.te", "semodule_package -o #{module_name}.pp -m #{module_name}.mod"],
          limitations: payload[:limitations], provenance: payload[:entries] }
      elsif format == "json"
        payload = { filename: "secentral-draft-#{draft.id}.json", content: JSON.pretty_generate(payload),
          validation_status: "semantic_only", build_steps: [], limitations: payload[:limitations], provenance: payload[:entries] }
      else
        raise ArgumentError, "Unknown export format"
      end
      draft.update!(status: "exported")
      payload
    end
  end
end
