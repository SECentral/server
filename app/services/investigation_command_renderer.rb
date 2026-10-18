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
    when :port_classification, :socket_listeners
      protocol = @check[:protocol]
      port = @check[:port]
      return unless %w[tcp udp].include?(protocol) && port.is_a?(Integer) && port.between?(1, 65_535)

      if @check[:kind] == :port_classification
        "semanage port -l"
      elsif @check[:operation] == "name_bind"
        Shellwords.join([ "ss", protocol == "tcp" ? "-ltnp" : "-lunp", "sport = :#{port}" ])
      end
    end
  end
end
