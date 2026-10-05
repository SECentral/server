class EvaluatePolicyFactJob < ApplicationJob
  queue_as :default

  def perform(policy_fact_id)
    fact = PolicyFact.find_by(id: policy_fact_id)
    return unless fact

    fact.with_lock do
      return unless fact.status == "pending"

      artifact = PolicyArtifact.find_by(policy_identity: fact.policy_identity)
      result = if artifact
        PolicyRuleEvaluator.call(fact, artifact)
      else
        { status: "unavailable", matching_rules: [], rule_details: [], error_message: "policy artifact is unavailable" }
      end
      fact.update!(result.merge(evaluated_at: Time.current))
      Rails.logger.info("policy fact evaluated id=#{fact.id} identity=#{fact.policy_identity} permission=#{fact.permission} status=#{fact.status} evaluator=#{fact.evaluator_version}")
    end
  rescue StandardError => error
    fact&.update!(status: "error", error_message: error.message.truncate(500), evaluated_at: Time.current)
    Rails.logger.warn("policy fact evaluation failed id=#{fact&.id}: #{error.message}")
  end
end
