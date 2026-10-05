class DistributionCatalogCanonicalizer
  def self.call(catalog)
    new(catalog).call
  end

  def initialize(catalog)
    @catalog = catalog
  end

  def call
    encode({
      "collector_semantics_version" => @catalog.fetch("collector_semantics_version"),
      "families" => {
        "booleans" => {
          "complete" => @catalog.dig("families", "booleans", "complete"),
          "entries" => @catalog.dig("families", "booleans", "entries").sort_by { |entry| entry.fetch("name") }
        },
        "ports" => {
          "complete" => @catalog.dig("families", "ports", "complete"),
          "mappings" => @catalog.dig("families", "ports", "mappings").sort_by { |mapping| [mapping.fetch("protocol"), mapping.fetch("start"), mapping.fetch("end"), mapping.fetch("type")] }
        }
      },
      "platform" => @catalog.fetch("platform"),
      "policy" => @catalog.fetch("policy").merge("packages" => @catalog.dig("policy", "packages").sort_by { |package| [package.fetch("name"), package.fetch("epoch"), package.fetch("version"), package.fetch("release"), package.fetch("architecture")] })
    })
  end

  private

  def encode(value)
    case value
    when nil then "null"
    when true, false then value.to_s
    when Integer then value.to_s
    when String then encode_string(value)
    when Array then "[#{value.map { |item| encode(item) }.join(",")}]"
    when Hash then "{#{value.keys.sort_by(&:bytes).map { |key| "#{encode_string(key)}:#{encode(value.fetch(key))}" }.join(",")}}"
    else raise ArgumentError, "unsupported canonical JSON value #{value.class}"
    end
  end

  def encode_string(value)
    raise ArgumentError, "canonical JSON strings must be UTF-8" unless value.encoding == Encoding::UTF_8 && value.valid_encoding?

    "\"#{value.each_codepoint.map { |codepoint| escape(codepoint) }.join}\""
  end

  def escape(codepoint)
    return '\\"' if codepoint == 34
    return "\\\\" if codepoint == 92
    return "\\b" if codepoint == 8
    return "\\f" if codepoint == 12
    return "\\n" if codepoint == 10
    return "\\r" if codepoint == 13
    return "\\t" if codepoint == 9
    return format("\\u%04x", codepoint) if codepoint < 32

    codepoint.chr(Encoding::UTF_8)
  end
end
