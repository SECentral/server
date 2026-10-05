require "digest"
require "json"

# Serialization only. Builders choose fields/sets; ResolutionWorkflow decides freshness.
class ResolutionPlanBasis
  FORMAT_VERSION = 1

  def self.canonical(value)
    case value
    when Hash
      value.to_h { |key, item| [key.to_s, canonical(item)] }.sort.to_h
    when Array
      value.map { |item| canonical(item) }
    when String, Numeric, TrueClass, FalseClass, NilClass
      value
    else
      value.as_json
    end
  end

  def self.digest(value)
    Digest::SHA256.hexdigest(JSON.generate(canonical(value)))
  end

  # Explicit sets only: command/step arrays retain their meaningful ordering.
  def self.ordered_set(values)
    values.map { |value| canonical(value) }.uniq.sort_by { |value| JSON.generate(value) }
  end
end
