require "rails_helper"

RSpec.describe DistributionCatalogReference do
  let(:identity) { "sha256:" + "a" * 64 }
  let(:other_identity) { "sha256:" + "b" * 64 }

  around do |example|
    DistributionCatalogImport.delete_all
    DistributionCatalogBoolean.delete_all
    DistributionCatalogPort.delete_all
    DistributionCatalogRevision.delete_all
    example.run
    DistributionCatalogImport.delete_all
    DistributionCatalogBoolean.delete_all
    DistributionCatalogPort.delete_all
    DistributionCatalogRevision.delete_all
  end

  def revision(identity:, digest:, distribution: "rhel", boolean_default: false)
    DistributionCatalogRevision.create!(schema_version: 1, content_digest: digest, collector_semantics_version: 3, loaded_policy_digest: identity, policy_type: "targeted", kernel_policy_version: 33, distribution: distribution, major_version: "9", architecture: "x86_64", policy_packages: [{ "name" => "selinux-policy-targeted", "version" => "38.1.75" }], booleans_complete: true, ports_complete: true).tap do |catalog|
      catalog.distribution_catalog_booleans.create!(name: "httpd_can_network_connect", default_value: boolean_default, description: "Allow network")
      catalog.distribution_catalog_ports.create!(protocol: "tcp", start_port: 8080, end_port: 8080, selinux_type: "http_port_t")
    end
  end

  def host(identity:, booleans: [], boolean_status: "observed", mappings: [], port_status: "observed", stale: false)
    details = { "selinux" => { "policy_identity" => identity, "boolean_status" => boolean_status, "booleans" => booleans, "policy" => { "port_inventory" => { "status" => port_status, "mappings" => mappings } } } }
    observation = Struct.new(:host_snapshot, :stale?).new(Struct.new(:details).new(details), stale)
    Struct.new(:id, :hostname, :current_state_observation).new(1, "host-1", observation)
  end

  def mapping(type, port, provenance: "not_confirmed_custom")
    { "type" => type, "protocol" => "tcp", "ports" => [{ "start" => port, "end" => port, "provenance" => provenance }] }
  end

  it "adapts only an exact snapshot catalog and preserves its identity" do
    catalog = revision(identity: identity, digest: "sha256:" + "1" * 64)
    snapshot = HostSnapshot.new(details: { "selinux" => { "policy_identity" => identity } })

    reference = described_class.for_snapshot(snapshot)

    expect(reference.boolean_catalog).to include("reference_source" => "distribution_catalog", "content_digest" => catalog.content_digest, "loaded_policy_digest" => identity, "distribution_catalog_revision_id" => catalog.id, "booleans" => [{ "name" => "httpd_can_network_connect", "default" => false, "description" => "Allow network" }])
    expect(reference.port_catalog).to include("completeness" => { "tcp" => "complete", "udp" => "complete", "sctp" => "complete", "dccp" => "complete" }, "mappings" => [{ "protocol" => "tcp", "start" => 8080, "end" => 8080, "type" => "http_port_t" }])
    expect(described_class.for_snapshot(HostSnapshot.new(details: { "selinux" => { "policy_identity" => other_identity } }))).to be_nil
  end

  it "uses one compatible major-release family when raw policy identity differs" do
    catalog = revision(identity: identity, digest: "sha256:" + "5" * 64, distribution: "almalinux")
    snapshot = HostSnapshot.new(details: { "platform" => { "os_id" => "almalinux", "os_version" => "9.3", "architecture" => "amd64" }, "selinux" => { "policy_identity" => other_identity, "configured_policy_type" => "targeted" } })

    reference = described_class.for_snapshot(snapshot)

    expect(reference).to have_attributes(revision: catalog, applicability: "major_release")
    expect(reference.boolean_catalog).to include("applicability" => "major_release")
  end

  it "does not choose between incompatible major-release families" do
    revision(identity: identity, digest: "sha256:" + "6" * 64, distribution: "almalinux")
    revision(identity: other_identity, digest: "sha256:" + "7" * 64, distribution: "almalinux", boolean_default: true)
    snapshot = HostSnapshot.new(details: { "platform" => { "os_id" => "almalinux", "os_version" => "9.3", "architecture" => "x86_64" }, "selinux" => { "policy_identity" => "sha256:" + "c" * 64, "configured_policy_type" => "targeted" } })

    expect(described_class.for_snapshot(snapshot)).to be_nil
  end

  it "only returns imported catalog references" do
    expect(BooleanCatalog.for(identity)).to be_nil
    expect(PortCatalog.for(identity)).to be_nil

    catalog = revision(identity: identity, digest: "sha256:" + "2" * 64, boolean_default: true)

    expect(BooleanCatalog.for(identity)).to include("reference_source" => "distribution_catalog", "content_digest" => catalog.content_digest, "booleans" => [include("default" => true)])
    expect(PortCatalog.for(identity)).to include("reference_source" => "distribution_catalog", "content_digest" => catalog.content_digest)
    expect(BooleanCatalog.for(other_identity)).to be_nil
  end

  it "keeps reference comparison separate from observed boolean freshness and status" do
    revision(identity: identity, digest: "sha256:" + "3" * 64)
    observed = host(identity: identity, booleans: [{ "name" => "httpd_can_network_connect", "current" => true, "default" => false, "status" => "observed" }])
    matching = host(identity: identity, booleans: [{ "name" => "httpd_can_network_connect", "current" => false, "default" => false, "status" => "observed" }])
    unknown = host(identity: identity)
    unavailable = host(identity: identity, boolean_status: "unavailable")
    stale = host(identity: identity, stale: true)

    result = BooleanCatalogOverlay.call(hosts: [observed, matching, unknown, unavailable, stale], policy_identity: identity)
    row = result.dig(:observed, :rows).find { |item| item[:name] == "httpd_can_network_connect" }

    expect(result[:catalog]).to include("reference_source" => "distribution_catalog")
    expect(row[:catalog]).to include("default" => false)
    expect(row[:counts]).to include("on" => 1, "off" => 1, "unknown" => 1, "reference_difference" => 1, "reference_match" => 1, "unavailable" => 1, "stale" => 1)
  end

  it "reuses port comparison while preserving local provenance and partial observation" do
    revision(identity: identity, digest: "sha256:" + "4" * 64)
    matching = host(identity: identity, mappings: [mapping("http_port_t", 8080)])
    local = host(identity: identity, mappings: [mapping("my_app_port_t", 8080, provenance: "custom")])
    partial = host(identity: identity, mappings: [], port_status: "partial")

    result = PortCatalogOverlay.call(hosts: [matching, local, partial], policy_identity: identity)

    expect(result[:catalog]).to include("reference_source" => "distribution_catalog")
    expect(result.dig(:observed, :segments)).to include(include(relation: "matching_effective_type"), include(relation: "different_effective_type", local_classification: "custom"), include(relation: "comparison_unknown"))
  end
end
