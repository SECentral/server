class FleetExplanation
  def self.call(host_explanations)
    new(host_explanations).call
  end

  def initialize(host_explanations)
    @hosts = host_explanations
  end

  def call
    agreed = @hosts.select { |host| host[:status] == "agreement" }
    groups = agreed.group_by { |host| host[:occurrence_diagnoses].first[:agreement_signature] }.values.map do |hosts|
      { diagnosis: hosts.first[:diagnosis], hosts: hosts.map { |host| host_reference(host) }, occurrence_ids: hosts.flat_map { |host| host[:occurrence_diagnoses].map { |result| result[:occurrence_id] } } }
    end
    disagreeing = @hosts.select { |host| host[:status] == "disagreement" }.map { |host| host_reference(host) }
    insufficient = @hosts.select { |host| host[:status] == "insufficient_evidence" }.map { |host| host_reference(host).merge(occurrence_ids: host[:occurrence_diagnoses].map { |result| result[:occurrence_id] }) }
    state = if disagreeing.any? || groups.size > 1
      "disagreement"
    elsif agreed.any? && insufficient.any?
      "partially_explained"
    elsif agreed.any?
      "consistent"
    else
      "insufficient_evidence"
    end

    { state: state, affected_host_count: @hosts.size, host_status_counts: @hosts.map { |host| host[:status] }.tally,
      explanation_groups: groups, disagreeing_hosts: disagreeing, insufficient_evidence_hosts: insufficient }
  end

  private

  def host_reference(host)
    { host_id: host[:host_id], hostname: host[:hostname] }
  end
end
