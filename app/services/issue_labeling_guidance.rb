require "pathname"
require "shellwords"

class IssueLabelingGuidance
  ROOTS = %w[/var/www /srv /etc].freeze
  SUSPECT_TYPES = %w[user_home_t default_t].freeze

  def self.call(issue, paths:, observations: [])
    return unless issue.target_class == "file" && (Array(issue.permissions) & %w[read open write getattr]).any?
    return unless SUSPECT_TYPES.include?(issue.target_type)

    paths = Array(paths).select { |value| eligible_path?(value) }.uniq.sort
    path = paths.first
    return unless path

    conventional_type = issue.source_type == "httpd_t" && path.start_with?("/var/www/") ? "httpd_sys_content_t" : nil
    return if observations.any? do |item|
      next false unless item["path"] == path

      resolved_type = item["expected_context"].to_s.split(":", 4)[2]
      resolved_type == issue.target_type || (conventional_type && resolved_type != conventional_type)
    end

    escaped_path = Shellwords.escape(path)
    directory = Pathname.new(path).dirname.to_s
    commands = [
      { action: "inspect", label: "Check the configured label", command: "matchpathcon -- #{escaped_path}" },
      { action: "restore_targeted", label: "Restore this file's configured context", command: "restorecon -v -- #{escaped_path}" }
    ]
    recursive = !ROOTS.include?(directory) && directory != "/"
    if recursive
      commands << { action: "restore_recursive", label: "Restore contexts recursively in the parent directory", command: "restorecon -Rv -- #{Shellwords.escape(directory)}" }
    end

    {
      type: "probable_label_mismatch",
      title: "Investigation lead: probable label mismatch",
      path: path,
      observed_type: issue.target_type,
      conventional_type: conventional_type,
      summary: conventional_type ? "Files under /var/www/ commonly use #{conventional_type}. This is a convention, not a host-resolved expected label. Files moved from a home directory may retain user_home_t." : "This path is in a system-managed directory but was labeled #{issue.target_type}. Check its configured context before changing it.",
      path_count: paths.size,
      recursive_directory: recursive ? directory : nil,
      recursive_path_count: recursive ? paths.count { |value| value.start_with?("#{directory}/") } : 0,
      commands: commands
    }
  end

  def self.eligible_path?(value)
    return false unless value.is_a?(String) && value.start_with?("/") && !value.match?(/[\0\r\n]/)

    path = Pathname.new(value)
    return false unless path.cleanpath.to_s == value

    ROOTS.any? { |root| value.start_with?("#{root}/") }
  rescue ArgumentError
    false
  end
  private_class_method :eligible_path?
end
