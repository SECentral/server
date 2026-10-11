class CatalogDistributionSource
  class Invalid < StandardError; end

  Result = Data.define(:supported_count)

  def self.verify(directory)
    new(directory).verify
  end

  def initialize(directory)
    @directory = Pathname.new(directory).realpath
  end

  def verify
    supported = 0
    referenced = []
    @directory.glob("**/*.review.json").sort.each do |review_path|
      require_confined_file(review_path)
      bytes = review_path.open("rb") { |file| file.read(DistributionCatalogArtifact::MAX_BYTES + 1) }
      require_value(bytes.bytesize <= DistributionCatalogArtifact::MAX_BYTES, "review record too large")
      record = JSON.parse(bytes.force_encoding(Encoding::UTF_8), max_nesting: DistributionCatalogArtifact::MAX_NESTING, object_class: DistributionCatalogArtifact::UniqueObject)
      require_value(record.is_a?(Hash) && record["review_record_version"].is_a?(Integer) && record["review_record_version"] == 1, "unsupported review record")
      digest = record["content_digest"]
      require_value(digest.to_s.match?(/\Asha256:[0-9a-f]{64}\z/), "invalid review digest")
      require_value(review_path.basename.to_s == "#{digest.delete_prefix('sha256:')}.review.json", "review filename/digest mismatch")
      adjacent = review_path.sub_ext("").sub_ext(".json")
      relative = adjacent.relative_path_from(@directory).to_s
      require_value(relative.is_a?(String) && relative.match?(%r{\A[a-z0-9_-]+/[0-9]+/[a-z0-9_-]+/#{digest.delete_prefix('sha256:')}\.json\z}), "invalid artifact path")
      referenced << relative
      artifact_path = require_confined_file(adjacent)
      artifact = DistributionCatalogArtifact.read(artifact_path).validate!
      require_value(artifact.content_digest == digest, "review content digest mismatch")
      platform = artifact.catalog["platform"]
      require_value(relative == "#{platform['distribution']}/#{platform['major_version']}/#{artifact.catalog.dig('policy', 'type')}/#{digest.delete_prefix('sha256:')}.json", "artifact layout/platform mismatch")
      require_value(artifact.metadata.keys.sort == %w[collected_at collector_version], "distribution envelope contains unreviewed metadata")
      require_value(artifact.metadata["collector_version"].match?(/\A[a-zA-Z0-9._:+-]{1,120}\z/), "collector version contains nonportable text")
      validate_review(record, artifact)
      supported += 1
    end
    unreviewed = @directory.glob("**/*.json").reject { |path| path.to_s.end_with?(".review.json") || referenced.include?(path.relative_path_from(@directory).to_s) }
    require_value(unreviewed.empty?, "artifact lacks a review record")
    Result.new(supported)
  rescue JSON::ParserError, ArgumentError, DistributionCatalogArtifact::Invalid, Errno::ENOENT => error
    raise Invalid, "Invalid catalog distribution source: #{error.message}"
  end

  private

  def validate_review(record, artifact)
    review = record["review"]
    require_value(review.is_a?(Hash) && review["date"].is_a?(String) && review["date"].match?(/\A\d{4}-\d{2}-\d{2}\z/), "missing or invalid review date")
    Date.iso8601(review["date"])
    scope = review["scope"]
    require_value(scope.is_a?(Array) && scope.any? && scope.uniq == scope && scope.all? { |family| artifact.catalog["families"].key?(family) }, "review scope must name supported artifact families")
    require_value(record["known_limitations"].is_a?(Array) && record["known_limitations"].all? { |limit| limit.is_a?(String) && limit.present? }, "invalid limitations")
  end

  def require_confined_file(path)
    resolved = path.realpath
    require_value(resolved.to_s.start_with?("#{@directory}/") && resolved.file?, "file escapes source directory")
    resolved
  end

  def require_value(value, message)
    raise Invalid, message unless value
  end
end
