class Occurrence < ApplicationRecord
  belongs_to :organization
  belongs_to :host
  belongs_to :host_snapshot, optional: true
  belongs_to :raw_event
  belongs_to :normalized_denial
  belongs_to :issue, optional: true, counter_cache: :occurrences_count

  def policy_identity
    raw_event.checkpoint_policy_identity(host_snapshot)
  end
end
