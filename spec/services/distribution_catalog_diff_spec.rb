require "rails_helper"

RSpec.describe DistributionCatalogDiff do
  def revision(digest, policy_digest, package: "38.1.75-2.el9_8", boolean_default: false, port_type: "http_port_t")
    DistributionCatalogRevision.create!(schema_version: 1, content_digest: digest, collector_semantics_version: 3, loaded_policy_digest: policy_digest, policy_type: "targeted", kernel_policy_version: 33, distribution: "rhel", major_version: "9", architecture: "x86_64", policy_packages: [{ "name" => "selinux-policy-targeted", "version" => package }], booleans_complete: true, ports_complete: true).tap do |catalog|
      catalog.distribution_catalog_booleans.create!(name: "httpd_can_network_connect", default_value: boolean_default, description: "Allow network")
      catalog.distribution_catalog_ports.create!(protocol: "tcp", start_port: 80, end_port: 80, selinux_type: port_type)
    end
  end

  around do |example|
    DistributionCatalogImport.delete_all
    DistributionCatalogBoolean.delete_all
    DistributionCatalogPort.delete_all
    DistributionCatalogRevision.delete_all
    example.run
    DistributionCatalogBoolean.delete_all
    DistributionCatalogPort.delete_all
    DistributionCatalogRevision.delete_all
  end

  it "keeps policy changes distinct from empty family diffs" do
    left = revision("sha256:" + "1" * 64, "sha256:" + "a" * 64, package: "38.1.65-1.el9")
    right = revision("sha256:" + "2" * 64, "sha256:" + "b" * 64)

    expect(described_class.call(left, right)).to include(policy: include(loaded_policy_digest_changed: true, packages_changed: true), booleans: { added: [], removed: [], default_changed: [], description_changed: [] }, ports: include(added: [], removed: [], changed: []))
  end

  it "reports boolean and port changes" do
    left = revision("sha256:" + "1" * 64, "sha256:" + "a" * 64)
    right = revision("sha256:" + "2" * 64, "sha256:" + "b" * 64, boolean_default: true, port_type: "dns_port_t")

    expect(described_class.call(left, right)).to include(booleans: include(default_changed: ["httpd_can_network_connect"]), ports: include(changed: [include(protocol: "tcp", start: 80, end: 80, from_types: ["http_port_t"], to_types: ["dns_port_t"])]))
  end
end
