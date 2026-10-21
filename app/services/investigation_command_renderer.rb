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
    when :port_policy_alternatives
      source = @check[:source_type]
      object_class = @check[:object_class]
      operation = @check[:operation]
      return unless source.to_s.match?(/\A[A-Za-z][A-Za-z0-9_]*\z/) && %w[tcp_socket udp_socket].include?(object_class) && %w[name_bind name_connect].include?(operation)

      Shellwords.join([ "sesearch", "-A", "-s", source, "-c", object_class, "-p", operation ])
    when :port_classification, :port_local_classification, :socket_listeners
      protocol = @check[:protocol]
      port = @check[:port]
      return unless %w[tcp udp].include?(protocol) && port.is_a?(Integer) && port.between?(1, 65_535)

      if @check[:kind] == :port_classification
        "semanage port -l"
      elsif @check[:kind] == :port_local_classification
        "semanage port -l -C"
      elsif @check[:operation] == "name_bind"
        Shellwords.join([ "ss", protocol == "tcp" ? "-ltnp" : "-lunp", "sport = :#{port}" ])
      end
    end
  end
end
