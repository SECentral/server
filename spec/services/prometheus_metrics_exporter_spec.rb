require "rails_helper"

RSpec.describe PrometheusMetricsExporter do
  let(:result) do
    DomainMetricsQuery::Result.new(issues: { ["open", "suspicious_behavior"] => 2 }, regressed_issues: 1,
      occurrences: 8, ungrouped_occurrences: 1, hosts: 3,
      hosts_by_selinux_enforcement: { "enforcing" => 3 }, hosts_with_open_issues: 2, agent_installations: {})
  end

  it "emits the complete bounded contract with gauge metadata and zeros in deterministic order" do
    text = described_class.new.call(result)
    lines = text.lines.map(&:chomp)
    samples = lines.reject { |line| line.start_with?("#") }
    expect(samples.size).to eq(39)
    expect(lines.grep(/^# HELP /).size).to eq(8)
    expect(lines.grep(/^# TYPE .* gauge$/).size).to eq(8)
    expect(samples).to include('secentral_issues{status="open",disposition="suspicious_behavior"} 2',
      'secentral_issues{status="resolved",disposition="suspicious_behavior"} 0',
      'secentral_issues{status="ignored",disposition="mixed"} 0',
      'secentral_hosts_by_selinux_enforcement{state="unknown"} 0',
      'secentral_agent_installations{state="offline"} 0', 'secentral_regressed_issues 1')
    expect(text).to end_with("\n")
    expect(described_class.new.call(result)).to eq(text)
    expect(text).not_to include("secentral_issues_by_disposition", "_total", "hostname", "fingerprint", "http_request")
  end

  it "ignores arbitrary labels outside the fixed enums and escapes exposition label syntax" do
    result.issues[["secret-host", "sensitive-path"]] = 99
    expect(described_class.new.call(result)).not_to include("secret-host", "sensitive-path")
    expect(described_class.new.send(:escape, "a\\b\"c\nd")).to eq('a\\\\b\\"c\\nd')
  end
end
