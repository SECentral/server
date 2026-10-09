class DistributionCatalogArtifact
  SCHEMA_VERSION = 1
  COLLECTOR_SEMANTICS_VERSION = 3
  PORT_PROTOCOLS = %w[tcp udp sctp dccp].freeze
  MAX_BYTES = 2 * 1024 * 1024
  MAX_ENTRIES = 20_000
  MAX_PACKAGES = 256
  MAX_NESTING = 32

  class Invalid < StandardError
    attr_reader :code, :path

    def initialize(message, code: "invalid_artifact", path: "artifact")
      super(message)
      @code = code
      @path = path
    end
  end

  attr_reader :artifact, :catalog, :metadata, :content_digest, :schema_version

  def self.read(path)
    new(File.open(path, "rb") { |file| file.read(MAX_BYTES + 1).to_s }, source_path: path)
  end

  def initialize(artifact, source_path: nil)
    @artifact = artifact
    @source_path = source_path
  end

  attr_reader :source_path

  def validate!
    @error_code, @error_path = "invalid_artifact", "artifact"
    raise Invalid.new("Catalog exceeds 2 MiB", code: "upload_too_large") if @artifact.bytesize > MAX_BYTES
    raise Invalid.new("Catalog is empty", code: "empty_upload") if @artifact.empty?

    json = @artifact.dup.force_encoding(Encoding::UTF_8)
    raise Invalid.new("Catalog must be valid UTF-8", code: "invalid_encoding") unless json.valid_encoding?

    document = JSON.parse(json, max_nesting: MAX_NESTING)
    require_keys(document, %w[schema_version content_digest catalog metadata], "artifact")
    @schema_version = document["schema_version"]
    raise Invalid.new("Unsupported schema version", code: "unsupported_schema", path: "schema_version") unless @schema_version.is_a?(Integer) && @schema_version == SCHEMA_VERSION

    require_sha256(document["content_digest"], "content digest")
    @catalog = document.fetch("catalog")
    @metadata = document.fetch("metadata")
    validate_catalog!
    validate_metadata!
    @content_digest = "sha256:#{Digest::SHA256.hexdigest(DistributionCatalogCanonicalizer.call(@catalog))}"
    raise Invalid.new("Content digest mismatch", code: "digest_mismatch", path: "content_digest") unless @content_digest == document.fetch("content_digest")

    self
  rescue JSON::ParserError
    raise Invalid.new("Malformed JSON or nesting exceeds 32 levels", code: "malformed_json")
  rescue ArgumentError
    raise Invalid.new("Invalid canonical catalog content", path: "catalog")
  end

  private

  def validate_catalog!
    require_keys(@catalog, %w[collector_semantics_version policy platform families], "catalog")
    unless @catalog["collector_semantics_version"].is_a?(Integer) && @catalog["collector_semantics_version"] == COLLECTOR_SEMANTICS_VERSION
      raise Invalid.new("Unsupported collector semantics version", code: "unsupported_collector_semantics", path: "catalog.collector_semantics_version")
    end
    validate_policy!
    validate_platform!
    @error_code, @error_path = "invalid_artifact", "catalog.families"
    require_value(@catalog["families"].is_a?(Hash) && (@catalog["families"].keys - %w[booleans ports]).empty?, "unsupported catalog families")
    validate_booleans!
    validate_ports!
  end

  def validate_policy!
    @error_code, @error_path = "invalid_identity", "catalog.policy"
    policy = @catalog.fetch("policy")
    require_keys(policy, %w[loaded_policy_digest type kernel_policy_version packages], "policy")
    require_sha256(policy["loaded_policy_digest"], "loaded policy digest")
    require_string(policy["type"], "policy type")
    require_value(policy["kernel_policy_version"].is_a?(Integer) && policy["kernel_policy_version"].positive?, "kernel policy version")
    packages = policy["packages"]
    require_value(packages.is_a?(Array) && packages.length.between?(1, MAX_PACKAGES), "policy packages")
    packages.each { |package| require_package(package) }
    require_canonical(packages, packages.sort_by { |package| [package["name"], package["epoch"], package["version"], package["release"], package["architecture"]] }, "policy packages")
    require_value(packages.uniq == packages, "duplicate policy package")
  end

  def validate_platform!
    @error_code, @error_path = "invalid_identity", "catalog.platform"
    platform = @catalog.fetch("platform")
    require_keys(platform, %w[distribution major_version architecture], "platform")
    platform.each_value { |value| require_string(value, "platform identity") }
  end

  def validate_booleans!
    @error_code, @error_path = "invalid_boolean_family", "catalog.families.booleans"
    family = @catalog.dig("families", "booleans")
    require_value(!family.nil?, "boolean family missing")
    require_keys(family, %w[complete entries], "boolean family")
    require_value(family["complete"] == true, "boolean family incomplete")
    entries = family["entries"]
    require_value(entries.is_a?(Array) && entries.length <= MAX_ENTRIES, "boolean entries")
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
    @error_code, @error_path = "invalid_port_family", "catalog.families.ports"
    family = @catalog.dig("families", "ports")
    require_value(!family.nil?, "port family missing")
    require_keys(family, %w[complete mappings], "port family")
    require_value(family["complete"] == true, "port family incomplete")
    mappings = family["mappings"]
    require_value(mappings.is_a?(Array) && mappings.length <= MAX_ENTRIES, "port mappings")
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
    @error_code, @error_path = "invalid_provenance", "metadata"
    require_value(@metadata.is_a?(Hash), "metadata")
    require_string(@metadata["collector_version"], "collector version")
    require_string(@metadata["collected_at"], "collection timestamp")
    Time.iso8601(@metadata.fetch("collected_at"))
  rescue KeyError, ArgumentError
    raise Invalid.new("Invalid acquisition metadata", code: @error_code, path: @error_path)
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
    raise Invalid.new(message, code: @error_code, path: @error_path) unless value
  end
end
