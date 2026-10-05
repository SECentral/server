require "digest"

class FingerprintV3
  VERSION = 3
  REQUIRED = %i[source_type target_type target_class permissions].freeze

  def self.call(denial)
    new(denial).call
  end

  def initialize(denial)
    @denial = denial
  end

  def call
    missing = REQUIRED.reject { |field| present?(@denial[field]) }
    return { status: "ungroupable", missing: missing } if missing.any?

    permissions = @denial[:permissions].uniq.sort
    canonical = ["v#{VERSION}", @denial[:source_type], @denial[:target_type], @denial[:target_class], *permissions, ""].join("\0").b
    { status: "ok", version: VERSION, canonical: canonical, digest: Digest::SHA256.hexdigest(canonical) }
  end

  private

  def present?(value)
    value.is_a?(String) ? !value.empty? : value.is_a?(Array) && value.any?
  end
end
