require "open3"

# One bounded SELinux subprocess boundary; test limits may lower, never raise caps.
class SetoolsProcess
  MAX_OUTPUT = 1024 * 1024

  def self.call(*command, wall_seconds: 30, cpu_seconds: 30)
    output, error, status = Open3.capture3("python3", Rails.root.join("script/setools_process.py").to_s,
      wall_seconds.to_s, cpu_seconds.to_s, *command)
    [output, error].each { |text| text.force_encoding(Encoding::UTF_8) }
    raise "Invalid or oversized policy subprocess output" unless output.valid_encoding? && error.valid_encoding? && output.bytesize + error.bytesize <= MAX_OUTPUT

    [output, error, status]
  end
end
