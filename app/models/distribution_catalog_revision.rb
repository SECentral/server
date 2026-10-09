class DistributionCatalogRevision < ApplicationRecord
  PORT_PROTOCOLS = %w[tcp udp sctp dccp].freeze
  ReferenceSelection = Data.define(:revision, :applicability)

  has_many :distribution_catalog_booleans, -> { order(:name) }, dependent: :restrict_with_exception
  has_many :distribution_catalog_ports, -> { order(:protocol, :start_port, :end_port, :selinux_type) }, dependent: :restrict_with_exception
  has_many :distribution_catalog_imports, dependent: :restrict_with_exception
  has_one :catalog_management, dependent: :restrict_with_exception

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
    identity = snapshot&.details&.dig("selinux", "policy_identity")
    exact = active.find_by(loaded_policy_digest: identity) if identity.to_s.match?(/\Asha256:[0-9a-f]{64}\z/)
    return ReferenceSelection.new(exact, "exact") if exact

    details = snapshot&.details || {}
    platform = details.fetch("platform", {})
    selinux = details.fetch("selinux", {})
    distribution = platform["os_id"].to_s.downcase
    major_version = platform["os_version"].to_s.split(".").first
    architecture = normalize_architecture(platform["architecture"])
    policy_type = selinux["configured_policy_type"].to_s.downcase
    return if [distribution, major_version, architecture, policy_type].any?(&:blank?)

    candidates = active.where(distribution: distribution, major_version: major_version, policy_type: policy_type).order(:id).includes(:catalog_management, :distribution_catalog_booleans, :distribution_catalog_ports).select { |revision| normalize_architecture(revision.architecture) == architecture && revision.booleans_complete? && revision.ports_complete? }
    families = candidates.group_by(&:reference_family_digest)
    return unless families.one?

    ReferenceSelection.new(families.values.first.first, "major_release")
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
