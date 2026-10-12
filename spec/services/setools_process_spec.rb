require "rails_helper"
require "tempfile"

RSpec.describe SetoolsProcess do
  def run_helper(mode, *args, **limits)
    described_class.call("python3", Rails.root.join("spec/fixtures/policy_analysis_process.py").to_s, mode, *args, **limits)
  end

  it "returns only a successful helper's bounded stdout and separate stderr" do
    stdout, stderr, status = run_helper("normal")
    expect(status.success?).to be(true)
    expect(JSON.parse(stdout).fetch("domains")).to include("postgresql_t")
    expect(stderr).to eq("")
    stdout, _, status = run_helper("error")
    expect(status.success?).to be(false)
    expect(stdout).to eq("")
  end

  %w[hang fork_hang escaped_hang background cpu memory].each do |mode|
    it "reaps #{mode} helper and descendants without leaving even zombie PIDs" do
      Tempfile.create("policy-process-pids") do |file|
        stdout, stderr, status = run_helper(mode, file.path, wall_seconds: mode == "cpu" ? 5 : 2, cpu_seconds: 1)
        expect(status.success?).to eq(mode == "background")
        expect(stdout).to eq("") unless mode == "background"
        expect(stderr).to be_present unless mode == "background"
        expect(stderr).to include("signal/resource limit") if mode == "cpu"
        expect(stderr).to include("MemoryError") if mode == "memory"
        pids = JSON.parse(File.binread(file.path))
        expect(pids.length).to eq(mode.in?(%w[fork_hang escaped_hang background]) ? 2 : 1)
        pids.each { |pid| expect { Process.kill(0, pid) }.to raise_error(Errno::ESRCH) }
      end
    end
  end

  it "rejects combined stdout/stderr overflow and discards partial stdout" do
    Tempfile.create("policy-output-pid") do |file|
      stdout, stderr, status = run_helper("output", file.path)
      expect(status.success?).to be(false)
      expect(stdout).to eq("")
      expect(stderr).to include("1 MiB combined output bound")
      JSON.parse(File.binread(file.path)).each { |pid| expect { Process.kill(0, pid) }.to raise_error(Errno::ESRCH) }
    end
  end

  it "fails closed for missing executables and refuses raised resource caps" do
    _, _, status = described_class.call("/no-such-policy-executable")
    expect(status.exitstatus).to eq(2)
    _, stderr, status = run_helper("normal", wall_seconds: 31)
    expect(status.success?).to be(false)
    expect(stderr).to include("only be lowered")
  end

  it "rejects invalid UTF-8 output rather than making it parser input or cache diagnostics" do
    expect { run_helper("invalid_encoding") }.to raise_error(RuntimeError, /Invalid/)
  end
end
