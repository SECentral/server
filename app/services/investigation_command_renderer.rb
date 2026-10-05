require "shellwords"

class InvestigationCommandRenderer
  def self.call(check)
    new(check).call
  end

  def initialize(check)
    @check = check
  end

  def call
    case @check[:kind]
    when :current_file_label
      Shellwords.join([ "ls", "-lZ", @check.fetch(:target) ])
    when :parent_file_label
      Shellwords.join([ "ls", "-ldZ", @check.fetch(:target) ])
    when :expected_file_label
      Shellwords.join([ "matchpathcon", @check.fetch(:target) ])
    end
  end
end
