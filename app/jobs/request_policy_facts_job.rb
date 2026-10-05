class RequestPolicyFactsJob < ApplicationJob
  queue_as :default

  def perform(raw_event_ids: nil, issue_id: nil)
    if raw_event_ids
      PolicyFactRequest.for_events(RawEvent.where(id: raw_event_ids).includes(:host_snapshot, :normalized_denials).to_a)
    elsif issue_id
      issue = Issue.find_by(id: issue_id)
      PolicyFactRequest.for_issue(issue) if issue
    end
  rescue StandardError => error
    Rails.logger.warn("policy fact request failed: #{error.message}")
  end
end
