class DistributionCatalogArtifact
  SCHEMA_VERSION = 1
  COLLECTOR_SEMANTICS_VERSION = 3
  PORT_PROTOCOLS = %w[tcp udp sctp dccp].freeze

  class Invalid < StandardError; end

  attr_reader :artifact, :catalog, :metadata, :content_digest

  def self.read(path)
    new(File.binread(path), source_path: path)
  end

  def initialize(artifact, source_path: nil)
    @artifact = artifact
    @source_path = source_path
  end

  attr_reader :source_path

  def validate!
    document = JSON.parse(@artifact.force_encoding(Encoding::UTF_8))
    require_keys(document, %w[schema_version content_digest catalog metadata], "artifact")
    require_value(document["schema_version"] == SCHEMA_VERSION, "unsupported schema version")
    require_sha256(document["content_digest"], "content digest")
    @catalog = document.fetch("catalog")
    @metadata = document.fetch("metadata")
    validate_catalog!
    validate_metadata!
    @content_digest = "sha256:#{Digest::SHA256.hexdigest(DistributionCatalogCanonicalizer.call(@catalog))}"
    require_value(@content_digest == document.fetch("content_digest"), "content digest mismatch")
    self
  rescue JSON::ParserError, ArgumentError => error
    raise Invalid, error.message
  end

  private

  def validate_catalog!
    require_keys(@catalog, %w[collector_semantics_version policy platform families], "catalog")
    require_value(@catalog["collector_semantics_version"] == COLLECTOR_SEMANTICS_VERSION, "unsupported collector semantics version")
    validate_policy!
    validate_platform!
    validate_booleans!
    validate_ports!
  end

  def validate_policy!
    policy = @catalog.fetch("policy")
    require_keys(policy, %w[loaded_policy_digest type kernel_policy_version packages], "policy")
    require_sha256(policy["loaded_policy_digest"], "loaded policy digest")
    require_string(policy["type"], "policy type")
    require_value(policy["kernel_policy_version"].is_a?(Integer) && policy["kernel_policy_version"].positive?, "kernel policy version")
    packages = policy["packages"]
    require_value(packages.is_a?(Array) && packages.any?, "policy packages")
    packages.each { |package| require_package(package) }
    require_canonical(packages, packages.sort_by { |package| [package["name"], package["epoch"], package["version"], package["release"], package["architecture"]] }, "policy packages")
    require_value(packages.uniq == packages, "duplicate policy package")
  end

  def validate_platform!
    platform = @catalog.fetch("platform")
    require_keys(platform, %w[distribution major_version architecture], "platform")
    platform.each_value { |value| require_string(value, "platform identity") }
  end

  def validate_booleans!
    family = @catalog.dig("families", "booleans")
    require_keys(family, %w[complete entries], "boolean family")
    require_value(family["complete"] == true, "boolean family incomplete")
    entries = family["entries"]
    require_value(entries.is_a?(Array), "boolean entries")
    entries.each do |entry|
      require_keys(entry, %w[name default description], "boolean entry")
      require_string(entry["name"], "boolean name")
      require_value(entry["default"] == true || entry["default"] == false, "boolean default")
      require_value(entry["description"].is_a?(String), "boolean description")
    end
    require_canonical(entries, entries.sort_by { |entry| entry["name"] }, "boolean entries")
    require_value(entries.map { |entry| entry["name"] }.uniq.length == entries.length, "duplicate boolean")
  end

  def validate_ports!
    family = @catalog.dig("families", "ports")
    require_keys(family, %w[complete mappings], "port family")
    require_value(family["complete"] == true, "port family incomplete")
    mappings = family["mappings"]
    require_value(mappings.is_a?(Array), "port mappings")
    mappings.each do |mapping|
      require_keys(mapping, %w[type protocol start end], "port mapping")
      require_string(mapping["type"], "port type")
      require_value(PORT_PROTOCOLS.include?(mapping["protocol"]), "port protocol")
      require_value(mapping["start"].is_a?(Integer) && mapping["end"].is_a?(Integer) && mapping["start"].between?(0, 65_535) && mapping["end"].between?(mapping["start"], 65_535), "port range")
    end
    require_canonical(mappings, mappings.sort_by { |mapping| [mapping["protocol"], mapping["start"], mapping["end"], mapping["type"]] }, "port mappings")
    require_value(mappings.uniq == mappings, "duplicate port mapping")
  end

  def validate_metadata!
    require_value(@metadata.is_a?(Hash), "metadata")
    require_string(@metadata["collector_version"], "collector version")
    Time.iso8601(@metadata.fetch("collected_at"))
  rescue KeyError, ArgumentError
    raise Invalid, "acquisition metadata"
  end

  def require_package(package)
    require_keys(package, %w[name epoch version release architecture], "policy package")
    package.each_value { |value| require_string(value, "policy package") }
  end

  def require_keys(value, keys, name)
    require_value(value.is_a?(Hash) && value.keys.sort == keys.sort, "invalid #{name}")
  end

  def require_sha256(value, name)
    require_value(value.is_a?(String) && value.match?(/\Asha256:[0-9a-f]{64}\z/), "invalid #{name}")
  end

  def require_string(value, name)
    require_value(value.is_a?(String) && !value.empty? && value.encoding == Encoding::UTF_8 && value.valid_encoding?, "invalid #{name}")
  end

  def require_canonical(value, expected, name)
    require_value(value == expected, "noncanonical #{name}")
  end

  def require_value(value, message)
    raise Invalid, message unless value
  end
end
