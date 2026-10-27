require "digest"
require "tempfile"

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
      return port_allows(file.path) if @fact.query_kind == PolicyFact::PORT_QUERY_KIND

      version, _, version_status = SetoolsProcess.call("sesearch", "--version")
      return unavailable("SETools sesearch is unavailable") unless version_status.success?

      output, error, status = SetoolsProcess.call(
          "sesearch", "--allow", "--source", @fact.source_type,
          "--target", @fact.target_type, "--class", @fact.object_class, "--perms", @fact.permission,
          file.path
        )
      unless status.success?
        return { status: "error", evaluator_version: version.strip,
          error_message: SetoolsProcess.failure_message(error, status, evaluator_version: "SETools #{version.strip}") }
      end

      rules = output.lines.map(&:strip).reject(&:empty?)
      raise "Invalid SETools rule output" unless rules.all? { |rule| rule.match?(RULE) }
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

  def port_allows(path)
    raise "Invalid port policy question" unless @fact.target_type == "port_type" &&
      @fact.object_class.in?(%w[tcp_socket udp_socket]) && @fact.permission.in?(%w[name_bind name_connect])

    output, error, status = SetoolsProcess.call("python3", Rails.root.join("script/policy_port_allows.py").to_s,
      path, @fact.source_type, @fact.object_class, @fact.permission)
    raise SetoolsProcess.failure_message(error, status) unless status.success?

    result = JSON.parse(output)
    rows = result.fetch("rules")
    raise "Invalid port policy result" unless rows.is_a?(Array) && result["evaluator_version"].is_a?(String)

    details = rows.map do |row|
      match = RULE.match(row.fetch("rule"))
      types = row.fetch("target_types")
      raise "Invalid port allow rule" unless match && match[3] == @fact.object_class &&
        match[4].delete("{}").split.include?(@fact.permission) && types.is_a?(Array) && types.any? &&
        types.all? { |type| type.is_a?(String) && type.match?(PolicyFactRequest::TYPE_FORMAT) }

      rule_details(row["rule"]).merge("target_types" => types.uniq.sort)
    end
    contexts = result.fetch("port_contexts")
    raise "Invalid policy port contexts" unless contexts.is_a?(Array) && contexts.all? do |context|
      context.is_a?(Hash) && context["type"].is_a?(String) && context["type"].match?(PolicyFactRequest::TYPE_FORMAT) &&
        context["start"].is_a?(Integer) && context["end"].is_a?(Integer) && context["start"].between?(0, 65_535) && context["end"].between?(context["start"], 65_535)
    end
    details << { "kind" => "port_contexts", "protocol" => @fact.object_class.delete_suffix("_socket"), "mappings" => contexts }
    { status: rows.empty? ? "no_match" : "matched", matching_rules: rows.map { |row| row["rule"] },
      rule_details: details, evaluator_version: result["evaluator_version"], error_message: nil }
  end

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
