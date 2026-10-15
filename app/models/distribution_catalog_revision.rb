class DistributionCatalogRevision < ApplicationRecord
  PORT_PROTOCOLS = %w[tcp udp sctp dccp].freeze

  has_many :distribution_catalog_booleans, -> { order(:name) }, dependent: :restrict_with_exception
  has_many :distribution_catalog_ports, -> { order(:protocol, :start_port, :end_port, :selinux_type) }, dependent: :restrict_with_exception
  has_many :distribution_catalog_imports, dependent: :restrict_with_exception
  has_one :catalog_management, dependent: :restrict_with_exception
  has_one :catalog_policy_artifact, dependent: :restrict_with_exception

  def reference_permissive_domains
    family = effective_permissive_domains
    evidence = { policy_identity: loaded_policy_digest, provenance: "inline_catalog_extraction",
      catalog_revision_id: id, content_digest: content_digest, evaluated_at: nil, semantics_version: nil, evaluator_version: nil }
    unless collector_semantics_version == DistributionCatalogArtifact::COLLECTOR_SEMANTICS_VERSION && family.is_a?(Hash) && family["complete"] == true &&
        PolicyPermissiveDomainAnalyzer.valid_domains?(family["domains"]) && family["domains"] == family["domains"].uniq.sort &&
        PolicyPermissiveDomainAnalyzer.valid_evaluator_version?(family["evaluator_version"])
      return evidence.merge(status: "unavailable", reason: "reference_inline_facts_unavailable", domains: nil)
    end

    evidence.merge(status: "observed", reason: nil, domains: family.fetch("domains"),
      semantics_version: family["extractor_semantics_version"], evaluator_version: family.fetch("evaluator_version"))
  end

  def reference_policy_artifact
    identity = { catalog_revision_id: id, content_digest: content_digest, expected_policy_digest: loaded_policy_digest }
    companion = catalog_policy_artifact
    return identity.merge(status: "unavailable", reason: "reference_policy_artifact_unavailable") unless companion

    artifact = companion.policy_artifact.verify_bytes!
    return identity.merge(status: "unavailable", reason: "reference_policy_artifact_invalid") unless artifact.policy_identity == loaded_policy_digest

    identity.merge(status: "available", reason: nil, policy_artifact_id: artifact.id, policy_artifact_digest: artifact.policy_identity,
      source_kind: companion.source_kind, acquisition_basis: companion.acquisition_basis,
      attached_by: companion.attached_by, attached_at: companion.created_at)
  rescue PolicyArtifact::InvalidBytes
    identity.merge(status: "unavailable", reason: "reference_policy_artifact_invalid")
  end

  scope :active, -> { joins(:catalog_management).where(catalog_managements: { lifecycle: "active" }) }

  validates :content_digest, :loaded_policy_digest, presence: true

  before_update { raise ActiveRecord::ReadOnlyRecord, self }
  before_destroy { raise ActiveRecord::ReadOnlyRecord, self }
  attr_accessor :initial_display_name
  after_create { create_catalog_management!(display_name: initial_display_name || default_display_name) }

  def self.for_snapshot(snapshot)
    identity = snapshot&.details&.dig("selinux", "policy_identity")
    return unless identity.to_s.match?(/\Asha256:[0-9a-f]{64}\z/)

    find_by(loaded_policy_digest: identity)
  end

  def self.reference_for_snapshot(snapshot)
    CatalogReferenceSelection.call(snapshot: snapshot)
  end

  def self.normalize_architecture(value)
    { "amd64" => "x86_64", "arm64" => "aarch64" }.fetch(value.to_s.downcase, value.to_s.downcase)
  end

  def port_catalog_completeness
    PORT_PROTOCOLS.index_with { "complete" } if ports_complete?
  end

  def display_name
    catalog_management.display_name
  end

  def default_display_name
    display = { "almalinux" => "AlmaLinux", "rhel" => "RHEL" }.fetch(distribution, distribution.titleize)
    [display, major_version].compact.join(" ")
  end

  def port_catalog_mappings
    distribution_catalog_ports.map { |mapping| { protocol: mapping.protocol, start: mapping.start_port, end: mapping.end_port, type: mapping.selinux_type } }
  end

  def reference_family_digest
    Digest::SHA256.hexdigest(JSON.generate(
      booleans_complete: booleans_complete?,
      ports_complete: ports_complete?,
      booleans: distribution_catalog_booleans.map { |entry| [entry.name, entry.default_value, entry.description] },
      ports: distribution_catalog_ports.map { |entry| [entry.protocol, entry.start_port, entry.end_port, entry.selinux_type] }
    ))
  end
end
