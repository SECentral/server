require "rails_helper"
require "rake"

Rails.application.load_tasks

RSpec.describe "SECentral demo task", type: :request do
  before do
    sign_in_operator
    Rake::Task["secentral:demo:reset"].reenable
    Rake::Task["secentral:demo"].reenable
    Rake::Task["secentral:demo"].invoke
  end

  after do
    Rake::Task["secentral:demo:reset"].reenable
    Rake::Task["secentral:demo:reset"].invoke
  end

  it "creates a complete deterministic dataset" do
    demo = Organization.find_by!(name: "SECentral Demo")

    expect(demo.hosts.count).to eq(19)
    expect(demo.issues.count).to be >= 8
    expect(demo.occurrences.count).to be >= 20
    expect(demo.issues.where(status: "ignored").count).to eq(1)
    expect(demo.issues.where(regressions_count: 1).count).to eq(1)
    expect(RawAuditRecord.where(raw_event_id: demo.raw_events).where("convert_from(payload, 'UTF8') LIKE ?", "%systemd-nsresou%").count).to be > 0

    expect(demo.issues.map { |issue| IssueDiagnosis.call(issue) }.compact).to be_empty
    expect(demo.raw_events.pluck(:policy_evaluations).flatten).to be_empty
    expect(demo.raw_events.pluck(:file_context_observations).flatten).to be_empty

    file_issue = demo.issues.find { |issue| issue.source_type == "httpd_t" && issue.target_type == "user_home_t" }
    expect(IssueDiagnosis.call(file_issue)).to be_nil

    connect_issue = demo.issues.find { |issue| issue.permissions == ["name_connect"] }
    explanations = IssueDiagnosis.per_host(connect_issue)
    rhel9 = explanations.find { |item| item[:hostname] == "rhel9-web-01.demo.secentral" }
    rhel8 = explanations.find { |item| item[:hostname] == "rhel8-web-02.demo.secentral" }
    expect(rhel9).to include(status: "insufficient_evidence", diagnosis: nil)
    expect(rhel8).to include(status: "insufficient_evidence", diagnosis: nil)
    expect(FleetExplanation.call(explanations)).to include(state: "insufficient_evidence")

    get "/api/v1/issues/#{connect_issue.id}/analysis"
    expect(JSON.parse(response.body).dig("fleet_explanation", "state")).to eq("insufficient_evidence")

    bind_issue = demo.issues.find { |issue| issue.permissions == ["name_bind"] }
    expect(IssueDiagnosis.call(bind_issue)).to be_nil

    database_issue = demo.issues.find { |issue| issue.source_type == "mysqld_t" }
    database_diagnosis = IssueDiagnosis.call(database_issue)
    expect(database_diagnosis).to be_nil
    expect(database_issue.occurrences).to all(satisfy { |occurrence| occurrence.normalized_denial.details.fetch("policy_evaluations").empty? })

    execute_issue = demo.issues.find { |issue| issue.permissions == ["execute"] }
    execute_diagnosis = IssueDiagnosis.call(execute_issue)
    expect(execute_diagnosis).to be_nil
    expect(IssueIntelligence.call(execute_issue).dig(:policy_evaluation, :status)).to eq("pending")
  end

  it "creates a believable reporting-state mix" do
    demo = Organization.find_by!(name: "SECentral Demo")
    states = demo.hosts.includes(:agent_installations).map { |host| host.agent_installations.first.reporting_state }

    expect(states.tally).to include("reporting" => 16, "stale" => 1, "offline" => 2)
    expect(HostSnapshotObservation.where(host_id: demo.hosts).count).to eq(19)
    expect(demo.hosts.find_by!(external_id: "rhel8-db-01").current_state_observation).to be_stale
    expect(demo.hosts.find_by!(external_id: "alma9-db-01").current_state_observation).to be_stale
    expect(demo.hosts.find_by!(external_id: "alma10-recovered-01").current_snapshot.details.dig("selinux", "boolean_status")).to eq("unavailable")
    expect(demo.hosts.find_by!(external_id: "rocky9-quiet-01").current_snapshot.details.dig("selinux", "booleans", 0)).to include("status" => "unknown", "current" => false)
    expect(demo.hosts.joins(:host_snapshots).where("host_snapshots.details #>> '{selinux,enforcement}' = ?", "permissive").count).to eq(1)
    expect(demo.hosts.joins(:host_snapshots).where("host_snapshots.details #>> '{selinux,enforcement}' = ?", "disabled").count).to eq(1)
    expect(demo.agent_installations.distinct.pluck(:agent_version)).to contain_exactly("demo-0.1.0", "demo-0.2.0")
    expect(demo.hosts.joins(:host_snapshots).where("host_snapshots.details #>> '{platform,os_version}' IN (?)", %w[8.10 8.9]).count).to be > 0
    expect(demo.hosts.joins(:host_snapshots).where("host_snapshots.details #>> '{platform,os_version}' IN (?)", %w[9.3 9.4 9.5 9.6]).count).to be > 0
    expect(demo.hosts.joins(:host_snapshots).where("host_snapshots.details #>> '{platform,os_version}' IN (?)", ["10.0"]).count).to be > 0
    expect(demo.hosts.joins(:host_snapshots).where("host_snapshots.details @> ?", { selinux: { policy: { modules: [{ name: "local_web", provenance: "custom" }] } } }.to_json).count).to be > 0

    catalog_identity = Digest::SHA256.hexdigest("rhel9-web").prepend("sha256:")
    overlay = BooleanCatalogOverlay.call(hosts: demo.hosts.includes(:host_snapshots).to_a, policy_identity: catalog_identity)
    network = overlay.dig(:observed, :rows).find { |row| row[:name] == "httpd_can_network_connect" }
    expect(overlay[:catalog]).to include(available: false, completeness: "unavailable")
    expect(network[:counts].slice("on", "off", "unknown", "unavailable", "stale")).to eq("on" => 1, "off" => 1, "unknown" => 1, "unavailable" => 1, "stale" => 1)
    expect(overlay.dig(:observed, :unmatched_observed_names)).to include("nis_enabled")
    expect(demo.hosts.find_by!(external_id: "rhel9-web-03").current_snapshot.details.dig("selinux", "policy_identity")).not_to eq(catalog_identity)

    ports = PortCatalogOverlay.call(hosts: demo.hosts.includes(:host_snapshots).to_a, policy_identity: catalog_identity)
    expect(ports[:catalog]).to include(available: false)
    mappings = ports.dig(:observed, :observed_mappings)
    expect(mappings).to include(include(type: "http_port_t", start: 80, end: 85, hostname: "rhel9-web-01.demo.secentral"))
    expect(mappings).to include(include(type: "my_app_port_t", start: 80, end: 90, provenance: "custom", hostname: "rocky9-web-01.demo.secentral"))
  end

  it "reprocesses retained events without changing evidence or lifecycle state" do
    demo = Organization.find_by!(name: "SECentral Demo")
    ignored = demo.issues.where(status: "ignored").first
    resolved = demo.issues.where(status: "open").where.not(id: ignored.id).first
    resolved.transition_to!("resolved")
    denial = NormalizedDenial.joins(:raw_event).find_by!(raw_events: { organization_id: demo.id }, source_type: "httpd_t", target_type: "user_home_t")
    details = denial.details.deep_dup
    syscall_evidence = details.fetch("syscall_evidence")
    denial.update!(details: details.merge("future_evidence" => { "normalizer_version" => 2 }, "syscall_evidence" => [{ "syscall" => "stale" }]))

    expect(details.fetch("syscall_evidence")).not_to be_empty
    expect(details).to include("permissive" => false, "enforcement_mode" => "enforcing")
    expect(details.fetch("event_file_contexts")).to be_empty
    expect(details.fetch("policy_evaluations")).to be_empty
    expect(details.fetch("evidence_provenance")).not_to be_empty

    Rake::Task["secentral:reprocess"].reenable
    Rake::Task["secentral:reprocess"].invoke

    expect(ignored.reload.status).to eq("ignored")
    expect(resolved.reload.status).to eq("resolved")
    expect(denial.reload.details).to eq(details.merge("future_evidence" => { "normalizer_version" => 2 }))
    expect(denial.details.fetch("syscall_evidence")).to eq(syscall_evidence)
    expect(demo.reload.occurrences.count).to be > 0
  end

  it "filters the host list to one demo host" do
    host = Organization.find_by!(name: "SECentral Demo").hosts.order(:id).first
    other_host = Organization.find_by!(name: "SECentral Demo").hosts.where.not(id: host.id).first

    get "/api/v1/hosts", params: { host_id: host.id }

    expect(response).to have_http_status(:ok)
    expect(response.body).to include(host.hostname)
    expect(response.body).not_to include(other_host.hostname)
  end
end
