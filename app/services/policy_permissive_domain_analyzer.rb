require "open3"
require "tempfile"
require "timeout"

class PolicyPermissiveDomainAnalyzer
  def self.call(artifact)
    bytes = artifact.artifact
    return { "status" => "unavailable", "error_message" => "policy artifact identity mismatch" } unless "sha256:#{Digest::SHA256.hexdigest(bytes)}" == artifact.policy_identity

    Tempfile.create(["secentral-permissive-policy-", ".bin"]) do |file|
      file.binmode
      file.write(bytes)
      file.flush
      output, error, status = Timeout.timeout(30) do
        Open3.capture3("python3", Rails.root.join("script/policy_permissive_domains.py").to_s, file.path)
      end
      unless status.success?
        return { "status" => status.exitstatus == 2 ? "unavailable" : "error", "error_message" => (error.presence || "Policy parser failed").truncate(500) }
      end
      result = JSON.parse(output)
      domains = result.fetch("domains")
      unless domains.is_a?(Array) && domains.all? { |name| name.is_a?(String) && name.match?(PolicyFactRequest::TYPE_FORMAT) }
        raise ArgumentError, "Invalid permissive type identifiers from policy parser"
      end
      { "status" => "observed", "domains" => domains.uniq.sort, "evaluator_version" => result.fetch("evaluator_version") }
    end
  rescue Errno::ENOENT
    { "status" => "unavailable", "error_message" => "SETools Python parser is unavailable" }
  rescue StandardError => error
    { "status" => "error", "error_message" => error.message.truncate(500) }
  end
end
