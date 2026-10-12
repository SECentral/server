require "tempfile"

class PolicyPermissiveDomainAnalyzer
  SEMANTICS_VERSION = 1

  def self.call(artifact)
    bytes = artifact.artifact
    PolicyArtifact.validate_bytes!(artifact.policy_identity, bytes)

    Tempfile.create(["secentral-permissive-policy-", ".bin"]) do |file|
      file.binmode
      file.write(bytes)
      file.flush
      output, error, status = SetoolsProcess.call("python3", Rails.root.join("script/policy_permissive_domains.py").to_s, file.path)
      raise "Oversized policy parser output" if output.bytesize + error.bytesize > SetoolsProcess::MAX_OUTPUT
      unless status.success?
        return { "status" => status.exitstatus == 2 ? "unavailable" : "error", "error_message" => (error.presence || "Policy parser failed").truncate(500) }
      end
      result = JSON.parse(output, max_nesting: 4, object_class: DistributionCatalogArtifact::UniqueObject)
      domains = result.fetch("domains")
      unless valid_domains?(domains) && valid_evaluator_version?(result["evaluator_version"])
        raise ArgumentError, "Invalid permissive type identifiers from policy parser"
      end
      { "status" => "observed", "domains" => domains.uniq.sort, "evaluator_version" => result.fetch("evaluator_version") }
    end
  rescue Errno::ENOENT
    { "status" => "unavailable", "error_message" => "SETools Python parser is unavailable" }
  rescue PolicyArtifact::InvalidBytes => error
    { "status" => "unavailable", "error_message" => error.message }
  rescue StandardError => error
    { "status" => "error", "error_message" => error.message.truncate(500) }
  end

  def self.valid_domains?(domains)
    domains.is_a?(Array) && domains.all? { |name| name.is_a?(String) && name.match?(PolicyFactRequest::TYPE_FORMAT) }
  end

  def self.valid_evaluator_version?(version)
    version.is_a?(String) && version.present? && version.length.between?(1, 120) && !version.match?(/[[:cntrl:]]/)
  end
end
