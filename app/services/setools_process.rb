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

  def self.failure_message(error, status, evaluator_version: nil)
    message = "Policy analysis failed (#{evaluator_version.presence || 'SETools'}, exit #{status.exitstatus})."
    if error.match?(/invalid policy|policy version|unsupported.*policy/i)
      message += " The SETools/libsepol toolchain may not support this policy format; malformed policy bytes are not established."
    end
    "#{message} #{error.strip}".strip.truncate(500)
  end
end
