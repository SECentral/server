class IssueQuery
  FILTER_KEYS = %w[q source_type target_type target_class permission path name target status new multiple_hosts os_id policy_version].freeze

  Result = Struct.new(:issues, :total_count, :page, :page_size, keyword_init: true)

  def initialize(filters: {}, host_id: nil, page: 1, limit: nil)
    @filters = filters.transform_keys(&:to_s)
    @filters["status"] = "open" if @filters["status"].to_s.blank?
    @host_id = host_id.presence
    @page = [page.to_i, 1].max
    @page_size = PageSize.parse(limit)
  end

  def call
    relation = scoped
    Result.new(issues: relation.offset((@page - 1) * @page_size).limit(@page_size).to_a, total_count: relation.count, page: @page, page_size: @page_size)
  end

  def count
    scoped.count
  end

  private

  def scoped
    issues = Issue.includes(occurrences: [:host, :normalized_denial]).order(last_seen_at: :desc, id: :desc)
    issues = issues.joins(:occurrences).where(occurrences: { host_id: @host_id }).distinct if @host_id
    apply_filters(issues)
  end

  def apply_filters(issues)
    if @filters["q"].present?
      query = "%#{ActiveRecord::Base.sanitize_sql_like(@filters["q"])}%"
      issues = issues.left_joins(occurrences: [:host, :normalized_denial]).where(
        "issues.source_type ILIKE :query OR issues.target_type ILIKE :query OR issues.target_class ILIKE :query OR issues.permissions::text ILIKE :query OR hosts.hostname ILIKE :query OR normalized_denials.target_paths::text ILIKE :query OR normalized_denials.details::text ILIKE :query",
        query: query
      ).distinct
    end
    issues = issues.where(source_type: @filters["source_type"]) if @filters["source_type"].present?
    issues = issues.where(target_type: @filters["target_type"]) if @filters["target_type"].present?
    issues = issues.where(target_class: @filters["target_class"]) if @filters["target_class"].present?
    filter = @filters["status"]
    if filter == "regressed"
      issues = issues.where(status: "open").where.not(reopened_at: nil)
        .where("resolved_at IS NULL OR reopened_at > resolved_at")
    elsif filter.present? && filter != "all"
      issues = issues.where(status: filter)
    end
    issues = issues.where(first_seen_at: 24.hours.ago..) if flag?(@filters["new"])
    if flag?(@filters["multiple_hosts"])
      issues = issues.where(id: Occurrence.group(:issue_id).having("COUNT(DISTINCT host_id) > 1").select(:issue_id))
    end
    issues = issues.where("issues.permissions @> ?", [@filters["permission"]].to_json) if @filters["permission"].present?
    if @filters["path"].present? || @filters["name"].present? || @filters["target"].present? || @filters["os_id"].present? || @filters["policy_version"].present?
      issues = issues.joins(occurrences: [:host_snapshot, :normalized_denial])
      issues = issues.where("normalized_denials.target_paths @> ?", [@filters["path"]].to_json) if @filters["path"].present?
      issues = issues.where("normalized_denials.details->'target_evidence'->'object_names' @> ?", [@filters["name"]].to_json) if @filters["name"].present?
      if @filters["target"].present?
        target = [@filters["target"]].to_json
        issues = issues.where("normalized_denials.details->'target_evidence'->'filesystem_paths' @> :target OR normalized_denials.details->'target_evidence'->'object_names' @> :target", target: target)
      end
      issues = issues.where("host_snapshots.details #>> '{platform,os_id}' = ?", @filters["os_id"]) if @filters["os_id"].present?
      issues = issues.where("host_snapshots.details #>> '{selinux,kernel_policy_version}' = ?", @filters["policy_version"]) if @filters["policy_version"].present?
      issues = issues.distinct
    end
    issues
  end

  def flag?(value)
    value.to_s.match?(/\A(1|true)\z/i)
  end
end
