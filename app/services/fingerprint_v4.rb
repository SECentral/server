require "digest"

class FingerprintV4
  def self.call(denial)
    canonical = ["v4", *denial.values_at(:source_type, :target_type, :target_class), ""].join("\0").b
    { version: 4, digest: Digest::SHA256.hexdigest(canonical) }
  end
end
