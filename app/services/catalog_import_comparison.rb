class CatalogImportComparison
  SAMPLE_LIMIT = 10
  CANDIDATE_LIMIT = 5

  def self.call(revision, created:)
    new(revision, created).call
  end

  def initialize(revision, created)
    @revision = revision
    @created = created
  end

  def call
    base = { to_revision: identity(@revision), from_revision: nil, changes: nil,
      basis: "unique_existing_same_context_revision", direction: "existing_to_imported", candidate_count: 0, candidates: [], candidates_truncated: false }
    return base.merge(status: "not_applicable", reason: "duplicate_import") unless @created
    return base.merge(status: "unavailable", reason: "imported_families_incomplete") unless @revision.booleans_complete? && @revision.ports_complete?

    aliases = CatalogReferenceSelection.architecture_aliases(@revision.architecture)
    # Lifecycle is selection eligibility, not semantic lineage. No active filter.
    scope = DistributionCatalogRevision.where(distribution: @revision.distribution, major_version: @revision.major_version,
      policy_type: @revision.policy_type, schema_version: @revision.schema_version,
      collector_semantics_version: @revision.collector_semantics_version, booleans_complete: true, ports_complete: true)
      .where("LOWER(architecture) IN (?)", aliases).where.not(id: @revision.id).order(:content_digest)
    candidates = scope.limit(CANDIDATE_LIMIT + 1).to_a
    return base.merge(status: "none", reason: "no_comparable_revision") if candidates.empty?

    count = candidates.size > CANDIDATE_LIMIT ? scope.count : candidates.size
    base = base.merge(candidate_count: count, candidates: candidates.first(CANDIDATE_LIMIT).map { |candidate| identity(candidate) }, candidates_truncated: count > CANDIDATE_LIMIT)
    return base.merge(status: "ambiguous", reason: "multiple_comparable_revisions") unless count == 1

    prior = candidates.first
    # Only one basis was found; load its normalized families once, not per entry.
    diff = DistributionCatalogDiff.call(prior, @revision)
    changes = %i[booleans ports].index_with do |family|
      diff.fetch(family).transform_values do |entries|
        { count: entries.size, samples: entries.first(SAMPLE_LIMIT).map { |entry| bounded_sample(entry) }, truncated: entries.size > SAMPLE_LIMIT }
      end
    end
    base.merge(status: "compared", reason: nil, from_revision: identity(prior), changes: changes.merge(policy: diff.fetch(:policy)))
  end

  private

  def bounded_sample(entry)
    return entry unless entry.is_a?(Hash) && entry.key?(:from_types)

    entry.merge(from_types: entry[:from_types].first(SAMPLE_LIMIT), to_types: entry[:to_types].first(SAMPLE_LIMIT),
      from_types_count: entry[:from_types].size, to_types_count: entry[:to_types].size,
      from_types_truncated: entry[:from_types].size > SAMPLE_LIMIT, to_types_truncated: entry[:to_types].size > SAMPLE_LIMIT)
  end

  def identity(revision)
    revision.attributes.slice("id", "content_digest", "loaded_policy_digest", "distribution", "major_version", "architecture", "policy_type")
  end
end
