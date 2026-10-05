require "digest"
require "open3"
require "tempfile"
require "timeout"

class PolicyRuleEvaluator
  RULE = /\Aallow\s+(\S+)\s+(\S+):(\S+)\s+(.+?);(?:\s+\[\s*(.*?)\s*\]:(True|False))?\z/

  def self.call(fact, artifact)
    new(fact, artifact).call
  end

  def initialize(fact, artifact)
    @fact = fact
    @artifact = artifact
  end

  def call
    return unavailable("policy artifact identity mismatch") unless identity_for(@artifact.artifact) == @fact.policy_identity

    Tempfile.create([ "secentral-policy-", ".bin" ]) do |file|
      file.binmode
      file.write(@artifact.artifact)
      file.flush
      version, version_status = Open3.capture2("sesearch", "--version")
      return unavailable("SETools sesearch is unavailable") unless version_status.success?

      output, error, status = Timeout.timeout(30) do
        Open3.capture3(
          "sesearch", "--allow", "--source", @fact.source_type,
          "--target", @fact.target_type, "--class", @fact.object_class, "--perms", @fact.permission,
          file.path
        )
      end
      return { status: "error", error_message: error.presence || "sesearch exited with #{status.exitstatus}" } unless status.success?

      rules = output.lines.map(&:strip).reject(&:empty?)
      {
        status: rules.empty? ? "no_match" : "matched",
        matching_rules: rules,
        rule_details: rules.map { |rule| rule_details(rule) },
        evaluator_version: version.strip,
        error_message: nil
      }
    end
  rescue Errno::ENOENT
    unavailable("SETools sesearch is unavailable")
  rescue StandardError => error
    { status: "error", error_message: error.message.truncate(500) }
  end

  private

  def rule_details(rule)
    match = RULE.match(rule)
    return { "rule" => rule } unless match

    source, target, object_class, permissions, expression, branch = match.captures
    {
      "rule" => rule,
      "source_symbol" => source,
      "target_symbol" => target,
      "object_class" => object_class,
      "permissions" => permissions.delete("{}").split,
      "source_match" => source == @fact.source_type ? "type" : "attribute",
      "target_match" => target == @fact.target_type ? "type" : "attribute",
      "conditional_expression" => expression,
      "conditional_branch" => branch
    }
  end

  def unavailable(message)
    { status: "unavailable", matching_rules: [], rule_details: [], error_message: message }
  end

  def identity_for(bytes)
    "sha256:#{Digest::SHA256.hexdigest(bytes)}"
  end
end
