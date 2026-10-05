require "rails_helper"

RSpec.describe IssueHypotheses do
  let(:issue) { instance_double(Issue) }

  it "emits a bounded policy correlation hypothesis from its signal" do
    intelligence = { fleet: { with_occurrence_modules: {}, without_occurrence_modules: {}, hosts_with_occurrence: 3, hosts_without_occurrence: 7 }, process_evidence: { "commands" => [], "executables" => [], "pids" => [], "source_contexts" => [] } }
    triage = { signals: [{ code: "policy_version_correlation", evidence: { correlations: [{ policy_version: "42" }] } }] }

    result = described_class.call(issue, intelligence: intelligence, triage: triage)

    expect(result).to include(include(kind: "policy_version_correlation", confidence_band: "medium", temporal_scope: "current_configuration_fleet"))
    expect(result.first[:missing_evidence]).to include("causal policy-change history")
  end

  it "emits a labeling mismatch only from event-associated label and mapping evidence" do
    intelligence = {
      paths: ["/var/www/index.html"],
       correlated_file_contexts: [{ "path" => "/var/www/index.html", "context" => "unconfined_u:object_r:user_home_t:s0", "status" => "observed", "expected_context" => "system_u:object_r:httpd_sys_content_t:s0", "expected_status" => "observed", host_id: 1 }],
      current_file_context_matches: [{ path: "/var/www/index.html", mapping: { "context" => "system_u:object_r:httpd_sys_content_t:s0" } }],
      fleet: { with_occurrence_modules: {}, without_occurrence_modules: {}, hosts_with_occurrence: 1, hosts_without_occurrence: 0 },
      process_evidence: empty_process
    }

    result = described_class.call(issue, intelligence: intelligence, triage: { signals: [] })

    expect(result.first).to include(kind: "labeling_mismatch", confidence_band: "low", temporal_scope: "correlated_occurrence_state")
    expect(result.first[:supporting_evidence].first[:fact]).to include("user_home_t", "httpd_sys_content_t")
  end

  it "returns insufficient evidence instead of guessing" do
    intelligence = { fleet: { with_occurrence_modules: {}, without_occurrence_modules: {} }, process_evidence: { "commands" => [], "executables" => [], "pids" => [], "source_contexts" => [] } }
    triage = { signals: [] }

    result = described_class.call(issue, intelligence: intelligence, triage: triage)

    expect(result.size).to eq(1)
    expect(result.first).to include(kind: "insufficient_evidence", confidence_band: "low")
  end

  it "emits a custom-policy hypothesis when module prevalence differs" do
    intelligence = { fleet: { with_occurrence_modules: { ["local_web", 400, "custom"] => 3 }, without_occurrence_modules: { ["local_web", 400, "custom"] => 0 }, hosts_with_occurrence: 3, hosts_without_occurrence: 7 }, process_evidence: empty_process }

    result = described_class.call(issue, intelligence: intelligence, triage: { signals: [] })

    expect(result.first).to include(kind: "custom_policy_difference", confidence_band: "low")
    expect(result.first[:supporting_evidence].first[:fact]).to include("local_web")
  end

  it "emits a local file-context hypothesis only with two cohorts" do
    intelligence = { fleet: { with_occurrence_file_contexts: { ["/srv", "all files", "system_u:object_r:httpd_sys_content_t:s0", "custom"] => 3 }, without_occurrence_file_contexts: { ["/srv", "all files", "system_u:object_r:var_t:s0", "custom"] => 0 }, hosts_with_occurrence: 3, hosts_without_occurrence: 7, with_occurrence_modules: {}, without_occurrence_modules: {} }, process_evidence: empty_process }

    result = described_class.call(issue, intelligence: intelligence, triage: { signals: [] })

    expect(result).to include(include(kind: "local_file_context_difference", confidence_band: "low"))
    expect(result.find { |item| item[:kind] == "local_file_context_difference" }[:supporting_evidence].first[:fact]).to include("/srv", "3/3", "0/7")
  end

  it "does not infer custom policy from an empty comparison cohort" do
    intelligence = { fleet: { with_occurrence_modules: { ["cockpit", 200, "unknown"] => 1 }, without_occurrence_modules: {}, hosts_with_occurrence: 1, hosts_without_occurrence: 0 }, process_evidence: empty_process }

    result = described_class.call(issue, intelligence: intelligence, triage: { signals: [] })

    expect(result).to include(include(kind: "insufficient_evidence"))
  end

  it "emits application behavior only with process evidence and a behavior signal" do
    intelligence = { fleet: { with_occurrence_modules: {}, without_occurrence_modules: {} }, process_evidence: empty_process.merge("executables" => ["/usr/sbin/httpd"]) }
    triage = { signals: [{ code: "host_concentration", evidence: { percentage: 100 } }] }

    result = described_class.call(issue, intelligence: intelligence, triage: triage)

    expect(result.first).to include(kind: "application_behavior_change", label: "Process-associated occurrence pattern", temporal_scope: "recent_and_baseline_occurrences")
    expect(result.first[:supporting_evidence].first[:fact]).to include("/usr/sbin/httpd", "Host concentration")
  end

  def empty_process
    { "commands" => [], "executables" => [], "pids" => [], "source_contexts" => [] }
  end
end
