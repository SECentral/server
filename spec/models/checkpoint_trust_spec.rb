require "rails_helper"

RSpec.describe CheckpointTrust do
  let(:state) do
    { "selinux" => { "policy_identity" => "sha256:#{'a' * 64}", "enforcement" => "enforcing",
      "boolean_status" => "observed", "booleans" => [{ "name" => "nis_enabled", "status" => "observed", "current" => false }],
      "policy" => { "port_inventory" => { "status" => "observed", "mappings" => [] } } } }
  end
  def trust(details, fields = [])
    described_class.new(HostSnapshot.new(details: details), fields)
  end

  described_class::TRANSITION_FIELDS.each do |family, fields|
    it "invalidates only #{family}'s documented dimensions without mutating evidence" do
      original = Marshal.dump(state)
      value = trust(state, described_class.fields_for(family))
      described_class::FIELDS.each { |field| expect(value.trusted?(field)).to eq(!fields.include?(field)) }
      expect(Marshal.dump(state)).to eq(original)
      expect(described_class.fields_for([family, family])).to eq(fields.sort)
    end
  end

  it "distinguishes observation availability from absence of a known invalidation" do
    absent = trust({})
    described_class::FIELDS.each { |field| expect(absent.trusted?(field)).to be(false) }
    expect { absent.trusted?(:artifact_upload) }.to raise_error(ArgumentError)
    partial = state.deep_dup
    partial["selinux"]["policy"]["port_inventory"] = { "status" => "partial", "mappings" => [] }
    expect(trust(partial).trusted?(:ports)).to be(false)
    expect(trust(partial).ports["status"]).to eq("partial")
    partial["selinux"]["booleans"][0]["current"] = nil
    expect(trust(partial).trusted?(:booleans)).to be(false)
    expect(trust(partial).trusted?(:policy_identity)).to be(true)
  end

  it "keeps SQL activity readiness identical to value-object readiness" do
    variants = [state, {}, state.deep_merge("selinux" => { "enforcement" => "unknown", "policy_identity" => nil }),
      state.deep_merge("selinux" => { "boolean_status" => "unavailable" }),
      state.deep_merge("selinux" => { "booleans" => [{ "name" => "nis_enabled", "status" => "observed", "current" => nil }] }),
      state.deep_merge("selinux" => { "policy" => { "port_inventory" => { "status" => "partial" } } })]
    variants.each do |details|
      quoted = ActiveRecord::Base.connection.quote(details.to_json)
      fields = ActiveRecord::Base.connection.select_value("SELECT array_to_json(#{described_class.observed_fields_sql("#{quoted}::jsonb")})")
      expected = described_class::FIELDS.select { |field| trust(details).trusted?(field) }
      expect(JSON.parse(fields)).to eq(expected)
    end
  end
end
