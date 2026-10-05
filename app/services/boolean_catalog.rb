class BooleanCatalog
  def self.for(policy_identity)
    return unless policy_identity.to_s.match?(/\Asha256:[0-9a-f]{64}\z/)

    DistributionCatalogReference.for_policy_identity(policy_identity)&.boolean_catalog
  end
end
