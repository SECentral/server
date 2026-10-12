require "rails_helper"

RSpec.describe CatalogReferenceSelection do
  let(:identity) { "sha256:" + "a" * 64 }
  after do
    DistributionCatalogImport.delete_all
    DistributionCatalogBoolean.delete_all
    DistributionCatalogPort.delete_all
    DistributionCatalogRevision.delete_all
  end

  def revision(index, default: false, complete: true, distribution: "almalinux", architecture: "x86_64", policy_type: "targeted")
    DistributionCatalogRevision.create!(schema_version: 1, collector_semantics_version: 3, content_digest: "sha256:#{index.to_s(16).rjust(64, '0')}", loaded_policy_digest: "sha256:#{(index + 100).to_s(16).rjust(64, '0')}", distribution: distribution, major_version: "9", architecture: architecture, policy_type: policy_type, kernel_policy_version: 33, policy_packages: [], booleans_complete: complete, ports_complete: true).tap do |record|
      record.distribution_catalog_booleans.create!(name: "httpd_can_network_connect", default_value: default, description: "Allow network")
      record.distribution_catalog_ports.create!(protocol: "tcp", start_port: 8080, end_port: 8080, selinux_type: "http_port_t")
    end
  end

  def snapshot(policy_identity: identity, boolean_status: "observed", port_status: "observed")
    HostSnapshot.new(details: { "platform" => { "os_id" => "almalinux", "os_version" => "9.3", "architecture" => "amd64" }, "selinux" => { "policy_identity" => policy_identity, "configured_policy_type" => "targeted", "boolean_status" => boolean_status, "booleans" => [{ "name" => "httpd_can_network_connect", "current" => false, "status" => "observed" }], "policy" => { "port_inventory" => { "status" => port_status, "mappings" => [] } } } })
  end

  it "selects active exact identity before incompatible fallback candidates, preserving archive-independent lookup" do
    exact = revision(1)
    revision(2, default: true)
    host_snapshot = snapshot(policy_identity: exact.loaded_policy_digest)
    result = described_class.call(snapshot: host_snapshot)
    expect(result).to have_attributes(mode: "automatic", status: "selected", revision: exact, basis: "exact_policy_identity", policy_identity_match: true)
    expect(result.family("booleans")).to include(status: "comparable", comparison_allowed: true)
    exact.catalog_management.change!(lifecycle: "archived", changed_by: "test")
    expect(described_class.call(snapshot: host_snapshot).basis).to eq("major_release_family_agreement")
    expect(DistributionCatalogRevision.for_snapshot(host_snapshot)).to eq(exact)
    exact.catalog_management.change!(lifecycle: "active", changed_by: "test")
    expect(described_class.call(snapshot: host_snapshot).revision).to eq(exact)
  end

  it "collapses all equivalent complete families without package/recency preference" do
    first = revision(1)
    revision(2)
    result = described_class.call(snapshot: snapshot)
    expect(result).to have_attributes(status: "selected", revision: first, basis: "major_release_family_agreement", candidate_count: 2, policy_identity_match: false)
    expect(result.as_json[:equivalence_asserted]).to be(false)
    expect(result.family("effective_permissive_domains")).to include(status: "unknown", comparison_allowed: false, reason: "effective_policy_requires_exact_reference")
    expect(result.family("future_policy_family")).to include(status: "unsupported", comparison_allowed: false)
  end

  it "exposes bounded incompatible candidates and changes eligibility on archive/unarchive" do
    7.times { |index| revision(index + 1, default: index.odd?) }
    result = described_class.call(snapshot: snapshot)
    expect(result).to have_attributes(status: "ambiguous", revision: nil, candidate_count: 7, reason: "incompatible_candidate_families")
    expect(result.candidates.size).to eq(5)
    expect(result.as_json[:candidates_truncated]).to be(true)
    DistributionCatalogRevision.where(content_digest: [2, 4, 6].map { |index| "sha256:#{index.to_s(16).rjust(64, '0')}" }).each { |record| record.catalog_management.change!(lifecycle: "archived", changed_by: "test") }
    expect(described_class.call(snapshot: snapshot).status).to eq("selected")
  end

  it "distinguishes absent, archived-only, incomplete-family and missing host/context states" do
    expect(described_class.call(snapshot: snapshot)).to have_attributes(status: "absent", reason: "no_matching_candidates")
    record = revision(1, complete: false)
    expect(described_class.call(snapshot: snapshot)).to have_attributes(status: "unavailable", reason: "incomplete_reference_families")
    record.catalog_management.change!(lifecycle: "archived", changed_by: "test")
    expect(described_class.call(snapshot: snapshot)).to have_attributes(status: "absent", reason: "archived_only")
    expect(described_class.call(snapshot: snapshot(policy_identity: nil))).to have_attributes(status: "unavailable", reason: "host_policy_identity_unavailable")
    unknown = HostSnapshot.new(details: { "selinux" => { "policy_identity" => identity } })
    expect(described_class.call(snapshot: unknown)).to have_attributes(status: "unavailable", reason: "platform_context_missing")
  end

  it "uses the explicit target without automatic substitution or equivalence assertions" do
    automatic = revision(1)
    chosen = revision(2, distribution: "rhel")
    result = described_class.call(snapshot: snapshot(policy_identity: automatic.loaded_policy_digest), revision_id: chosen.id)
    expect(result).to have_attributes(mode: "explicit", status: "selected", revision: chosen, basis: "explicit_revision", policy_identity_match: false)
    expect(result.as_json[:equivalence_asserted]).to be(false)
    chosen.catalog_management.change!(lifecycle: "archived", changed_by: "test")
    expect(described_class.call(snapshot: snapshot, revision_id: chosen.id)).to have_attributes(status: "unavailable", revision: nil, reason: "archived_reference")
    expect { described_class.call(snapshot: snapshot, revision_id: "1.5") }.to raise_error(described_class::InvalidRevision)
    expect { described_class.call(snapshot: snapshot, revision_id: 9_223_372_036_854_775_808) }.to raise_error(described_class::InvalidRevision)
    expect { described_class.call(snapshot: snapshot, revision_id: 99_999) }.to raise_error(ActiveRecord::RecordNotFound)
  end

  it "keeps family usability separate from selection and does not restore raw identity after invalidation" do
    record = revision(1)
    %w[unknown unavailable partial].each do |state|
      result = described_class.call(snapshot: snapshot(boolean_status: state, port_status: state), revision_id: record.id)
      expect(result.status).to eq("selected")
      expect(result.family("booleans")[:status]).to eq(state == "partial" ? "incomplete" : state)
      expect(result.family("ports")[:comparison_allowed]).to eq(state == "partial")
    end
    expect(described_class.call(snapshot: snapshot, revision_id: record.id, stale: true).family("ports")).to include(status: "stale", comparison_allowed: false)
    trusted = CheckpointTrust.new(snapshot(policy_identity: record.loaded_policy_digest), ["policy_identity"]).selinux
    expect(described_class.call(snapshot: snapshot, selinux: trusted).status).to eq("unavailable")
    explicit = described_class.call(snapshot: snapshot, selinux: trusted, revision_id: record.id)
    expect(explicit).to have_attributes(status: "selected", policy_identity_match: nil)
    expect(explicit.family("booleans")).to include(status: "unknown", reason: "host_policy_identity_unavailable", comparison_allowed: false)
    incomplete = revision(2, complete: false)
    expect(described_class.call(snapshot: snapshot, revision_id: incomplete.id).family("booleans")).to include(status: "incomplete", comparison_allowed: false)
    incompatible = revision(3, policy_type: "mls")
    expect(described_class.call(snapshot: snapshot, revision_id: incompatible.id).family("ports")).to include(status: "unavailable", reason: "incompatible_policy_context")
  end

  it "preloads fallback facts without N+1 and returns summary-only bounded options" do
    4.times { |index| revision(index + 1) }
    sql = []
    subscriber = ActiveSupport::Notifications.subscribe("sql.active_record") { |*, payload| sql << payload[:sql] if payload[:sql].start_with?("SELECT") }
    result = described_class.call(snapshot: snapshot)
    expect(result.status).to eq("selected")
    family_queries = sql.select { |query| query.include?("distribution_catalog_booleans") || query.include?("distribution_catalog_ports") }
    expect(family_queries.size).to eq(2)
    sql.clear
    options = described_class.options(snapshot: snapshot, selinux: snapshot.details["selinux"])
    expect(options[:revisions].size).to eq(4)
    expect(sql.none? { |query| query.include?("distribution_catalog_booleans") || query.include?("distribution_catalog_ports") }).to be(true)
    expect(options[:revisions].first.keys).not_to include(:booleans, :ports)
  ensure
    ActiveSupport::Notifications.unsubscribe(subscriber) if subscriber
  end
end
