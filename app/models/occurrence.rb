class Occurrence < ApplicationRecord
  # Keep corrected interpretations out of live counts while retaining historical URLs.
  default_scope { where(superseded_at: nil) }

  belongs_to :organization
  belongs_to :host
  belongs_to :host_snapshot, optional: true
  belongs_to :raw_event
  belongs_to :normalized_denial
  belongs_to :issue, optional: true, counter_cache: :occurrences_count
  belongs_to :issue_signature, optional: true

  def policy_identity
    raw_event.checkpoint_policy_identity(host_snapshot)
  end
end
