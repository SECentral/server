require "rails_helper"

RSpec.describe NormalizedDenial do
  it "keeps AVC enforcement independent of the associated syscall outcome" do
    [[false, "no", "enforcing", "failed"], [true, "yes", "permissive", "succeeded"],
      [true, "no", "permissive", "failed"], [nil, nil, "unknown", "unknown"]].each do |permissive, success, mode, outcome|
      denial = described_class.new(details: { "permissive" => permissive, "syscall_evidence" => [{ "success" => success }] })
      expect(denial.enforcement_mode).to eq(mode)
      expect(denial.syscall_outcome).to eq(outcome)
    end
  end

  it "keeps missing, contradictory and partially unknown syscall evidence unknown" do
    [[], [{ "success" => "no" }, { "success" => "yes" }], [{ "success" => "no" }, {}],
      [{ "success" => "yes", "exit" => "-13" }], [{ "success" => "no", "exit" => "0" }]].each do |records|
      expect(described_class.syscall_outcome("syscall_evidence" => records)).to eq("unknown")
    end
  end

  it "does not choose between contradictory AVC mode interpretations" do
    expect(described_class.enforcement("permissive" => true, "enforcement_mode" => "enforcing")).to eq("unknown")
  end

  it "keeps conflicting record fields and syscall identities unknown" do
    result = AvcNormalizer.call(['type=AVC denied { read } permissive=1 permissive=0',
      'type=SYSCALL success=yes success=no exit=-13']).sole
    expect(result[:permissive]).to be_nil
    expect(described_class.syscall_outcome("syscall_evidence" => result[:syscall_evidence])).to eq("unknown")
    expect(described_class.syscall_outcome("syscall_evidence" => [
      { "syscall" => "2", "success" => "no" }, { "syscall" => "3", "success" => "no" }
    ])).to eq("unknown")
  end

  it "retains known mode and syscall evidence even when the AVC cannot be grouped" do
    result = AvcNormalizer.call(['type=AVC denied { read } permissive=1', 'type=SYSCALL success=yes exit=3']).sole
    expect(result).to include(status: "ungroupable", permissive: true)
    expect(described_class.syscall_outcome("syscall_evidence" => result[:syscall_evidence])).to eq("succeeded")
  end

  it "takes syscall outcomes only from SYSCALL records and retains their provenance" do
    records = [
      'type=AVC avc: denied { read } scontext=u:r:httpd_t:s0 tcontext=u:object_r:var_t:s0 tclass=file permissive=0 syscall=1 success=yes',
      'type=SYSCALL arch=c000003e syscall=2 success=no exit=-13'
    ]
    result = AvcNormalizer.call(records).sole
    expect(result[:syscall_evidence]).to eq([{ "arch" => "c000003e", "syscall" => "2", "success" => "no", "exit" => "-13", "source_record_position" => 1 }])
    expect(described_class.syscall_outcome("syscall_evidence" => result[:syscall_evidence])).to eq("failed")
  end
end
