class RequestResolutionPolicyFactsJob < ApplicationJob
  def perform(issue_id:)
    PolicyFactRequest.for_current_issue_hosts(Issue.find(issue_id))
  end
end
