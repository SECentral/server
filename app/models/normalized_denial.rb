class NormalizedDenial < ApplicationRecord
  belongs_to :raw_event
  has_one :occurrence, dependent: :restrict_with_exception

  validates :ordinal, :normalization_version, :status, presence: true

  def self.enforcement(details)
    recorded = details["enforcement_mode"]
    if %w[enforcing permissive].include?(recorded) && [true, false].include?(details["permissive"])
      return "unknown" if (recorded == "permissive") != details["permissive"]
    end
    case details["permissive"]
    when true then "permissive"
    when false then "enforcing"
    else
      mode = details["enforcement_mode"]
      %w[enforcing permissive].include?(mode) ? mode : "unknown"
    end
  end

  def self.syscall_outcome(details)
    evidence = Array(details["syscall_evidence"])
    return "unknown" if evidence.empty?
    return "unknown" if %w[arch syscall exit].any? do |field|
      evidence.filter_map { |record| record[field] if record.is_a?(Hash) }.uniq.size > 1
    end

    outcomes = evidence.map do |record|
      next "unknown" unless record.is_a?(Hash)
      outcome = case record["success"].to_s
      when "yes", "true", "1" then "succeeded"
      when "no", "false", "0" then "failed"
      else "unknown"
      end
      if record.key?("exit")
        exit_value = record["exit"].to_s
        next "unknown" unless exit_value.match?(/\A-?\d+\z/)
        next "unknown" if (outcome == "succeeded" && exit_value.to_i.negative?) || (outcome == "failed" && exit_value.to_i >= 0)
      end
      outcome
    end.uniq
    outcomes.one? ? outcomes.first : "unknown"
  end

  def enforcement_mode = self.class.enforcement(details)
  def syscall_outcome = self.class.syscall_outcome(details)
end
