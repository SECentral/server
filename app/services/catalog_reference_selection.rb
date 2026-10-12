class CatalogReferenceSelection
  CANDIDATE_LIMIT = 5
  OPTION_LIMIT = 50
  FAMILIES = %w[booleans ports].freeze
  Result = Data.define(:mode, :status, :revision, :basis, :reason, :candidates, :candidate_count, :context, :policy_identity_match, :families) do
    def applicability
      { "exact_policy_identity" => "exact", "major_release_family_agreement" => "major_release", "explicit_revision" => "explicit" }[basis]
    end

    def family(name)
      families.fetch(name.to_s, { status: "unsupported", reference_status: "unsupported", host_status: "not_evaluated", comparison_allowed: false, reason: "unsupported_reference_family" })
    end

    def as_json(*)
      { mode: mode, status: status, basis: basis, reason: reason,
        selected_revision: revision && CatalogReferenceSelection.identity(revision),
        candidates: candidates, candidate_count: candidate_count,
        candidates_truncated: candidate_count > candidates.size,
        context: context, policy_identity_match: policy_identity_match,
        equivalence_asserted: mode == "automatic" && basis == "exact_policy_identity",
        families: families }
    end
  end

  class InvalidRevision < StandardError; end

  def self.call(snapshot:, selinux: nil, revision_id: nil, stale: false)
    new(snapshot, selinux, revision_id, stale).call
  end

  def self.for_policy_identity(identity)
    new(nil, { "policy_identity" => identity, "boolean_status" => "not_evaluated", "policy" => { "port_inventory" => { "status" => "not_evaluated" } } }, nil, false).call
  end

  def self.identity(revision)
    { id: revision.id, display_name: revision.display_name, content_digest: revision.content_digest,
      loaded_policy_digest: revision.loaded_policy_digest, lifecycle: revision.catalog_management.lifecycle,
      distribution: revision.distribution, major_version: revision.major_version,
      architecture: revision.architecture, policy_type: revision.policy_type }
  end

  def self.options(snapshot:, selinux:)
    platform = snapshot&.details&.fetch("platform", {}) || {}
    aliases = architecture_aliases(platform["architecture"])
    relevance = DistributionCatalogRevision.sanitize_sql_array([
      "CASE WHEN distribution = ? AND LOWER(architecture) IN (?) AND policy_type = ? THEN 0 ELSE 1 END",
      platform["os_id"].to_s.downcase, aliases, selinux["configured_policy_type"].to_s.downcase
    ])
    revisions = DistributionCatalogRevision.active.select(:id, :content_digest, :loaded_policy_digest, :distribution, :major_version, :architecture, :policy_type)
      .order(Arel.sql(relevance), :id).preload(:catalog_management).limit(OPTION_LIMIT + 1).to_a
    { revisions: revisions.first(OPTION_LIMIT).map { |revision| identity(revision) }, truncated: revisions.size > OPTION_LIMIT }
  end

  def self.architecture_aliases(value)
    normalized = DistributionCatalogRevision.normalize_architecture(value)
    { "x86_64" => %w[x86_64 amd64], "aarch64" => %w[aarch64 arm64] }.fetch(normalized, [normalized])
  end

  def initialize(snapshot, selinux, revision_id, stale)
    @snapshot = snapshot
    @selinux = selinux || CheckpointTrust.new(snapshot).selinux
    @identity = @selinux["policy_identity"]
    @revision_id = revision_id
    @mode = revision_id.nil? ? "automatic" : "explicit"
    @stale = stale
    platform = snapshot&.details&.fetch("platform", {}) || {}
    @context = { distribution: platform["os_id"].to_s.downcase, major_version: platform["os_version"].to_s.split(".").first,
      architecture: DistributionCatalogRevision.normalize_architecture(platform["architecture"]), policy_type: @selinux["configured_policy_type"].to_s.downcase }
  end

  def call
    return explicit if @mode == "explicit"
    return result("unavailable", reason: "host_policy_identity_unavailable") unless valid_identity?

    exact = DistributionCatalogRevision.active.preload(:catalog_management).find_by(loaded_policy_digest: @identity)
    return result("selected", revision: exact, basis: "exact_policy_identity", candidates: [exact]) if exact

    archived_exact = DistributionCatalogRevision.includes(:catalog_management).find_by(loaded_policy_digest: @identity)
    return result("absent", reason: archived_exact ? "archived_only" : "no_matching_candidates", candidates: Array(archived_exact)) unless @snapshot

    if @context.values.any?(&:blank?)
      return result(archived_exact ? "absent" : "unavailable", reason: archived_exact ? "archived_only" : "platform_context_missing", candidates: Array(archived_exact))
    end
    scope = DistributionCatalogRevision.where(distribution: @context[:distribution], major_version: @context[:major_version], policy_type: @context[:policy_type])
      .where("LOWER(architecture) IN (?)", self.class.architecture_aliases(@context[:architecture]))
    active = scope.active.preload(:catalog_management).order(:id)
    # Separate preloads avoid Boolean × port row multiplication through the
    # lifecycle join while evaluating every eligible family's agreement.
    candidates = active.where(booleans_complete: true, ports_complete: true).preload(:distribution_catalog_booleans, :distribution_catalog_ports).to_a
    if candidates.empty?
      incomplete = active.limit(CANDIDATE_LIMIT).to_a
      return result("unavailable", reason: "incomplete_reference_families", candidates: incomplete, count: active.count) if incomplete.any?

      archived = scope.includes(:catalog_management).order(:id).limit(CANDIDATE_LIMIT).to_a
      return result("absent", reason: archived.any? || archived_exact ? "archived_only" : "no_matching_candidates", candidates: archived.presence || Array(archived_exact), count: archived.any? ? scope.count : nil)
    end
    families = candidates.group_by(&:reference_family_digest)
    return result("ambiguous", reason: "incompatible_candidate_families", candidates: candidates) unless families.one?

    # The representative is stable within an equivalent family, never an upgrade
    # or recency preference. Every eligible candidate participates in agreement.
    result("selected", revision: candidates.first, basis: "major_release_family_agreement", candidates: candidates)
  end

  private

  def explicit
    value = @revision_id.to_s
    raise InvalidRevision, "reference_revision_id must be a positive immutable revision ID" unless value.match?(/\A[1-9][0-9]{0,18}\z/) && value.to_i <= 9_223_372_036_854_775_807

    revision = DistributionCatalogRevision.includes(:catalog_management).find(value.to_i)
    return result("unavailable", reason: "archived_reference", candidates: [revision]) unless revision.catalog_management.lifecycle == "active"

    result("selected", revision: revision, basis: "explicit_revision", candidates: [revision])
  end

  def valid_identity?
    @identity.to_s.match?(/\Asha256:[0-9a-f]{64}\z/)
  end

  def result(status, revision: nil, basis: nil, reason: nil, candidates: [], count: nil)
    applicability = FAMILIES.index_with { |family| family_status(family, revision, basis) }
    Result.new(@mode, status, revision, basis, reason,
      candidates.first(CANDIDATE_LIMIT).map { |candidate| self.class.identity(candidate) }, count || candidates.size,
      @context, revision && valid_identity? ? revision.loaded_policy_digest == @identity : nil, applicability)
  end

  def family_status(family, revision, basis)
    host_status = family == "booleans" ? boolean_status : (@selinux.dig("policy", "port_inventory", "status") || "unknown")
    reference_status = revision ? (revision.public_send("#{family}_complete?") ? "complete" : "incomplete") : "unavailable"
    status, reason = if !revision
      ["unavailable", "reference_not_selected"]
    elsif reference_status != "complete"
      ["incomplete", "reference_family_incomplete"]
    elsif !valid_identity?
      ["unknown", "host_policy_identity_unavailable"]
    elsif basis == "explicit_revision" && incompatible_context?(revision)
      ["unavailable", "incompatible_policy_context"]
    elsif @stale
      ["stale", "stale_host_observation"]
    elsif host_status == "observed"
      ["comparable", nil]
    elsif host_status == "partial"
      ["incomplete", "partial_host_inventory"]
    else
      [host_status == "unavailable" ? "unavailable" : "unknown", "host_inventory_#{host_status}"]
    end
    { status: status, reference_status: reference_status, host_status: host_status,
      comparison_allowed: status == "comparable" || (status == "incomplete" && reason == "partial_host_inventory"), reason: reason }
  end

  def boolean_status
    status = @selinux["boolean_status"]
    entries = Array(@selinux["booleans"])
    valid = entries.all? { |entry| entry.is_a?(Hash) && entry["status"] == "observed" && entry["current"].in?([true, false]) }
    return valid ? "observed" : "partial" if status == "observed" || (status.nil? && entries.any?)

    status || "unknown"
  end

  def incompatible_context?(revision)
    (@context[:policy_type].present? && @context[:policy_type] != revision.policy_type) ||
      (@context[:architecture].present? && @context[:architecture] != DistributionCatalogRevision.normalize_architecture(revision.architecture))
  end
end
