require "rails_helper"

RSpec.describe CapabilityGuidance do
  let(:context) { "system_u:system_r:httpd_t:s0" }
  let(:avc) { "type=AVC avc: denied { net_admin } for pid=2012 comm=\"httpd\" capability=12 scontext=#{context} tcontext=#{context} tclass=capability permissive=1" }
  let(:syscall) { "type=SYSCALL arch=c000003e syscall=54 success=yes exit=0 a0=9 a1=1 a2=20 a3=7ffcdc40a3b4 pid=2012 comm=\"httpd\" exe=\"/usr/sbin/httpd\" subj=#{context}" }

  def guidance(records)
    denial = NormalizedDenial.new(source_context: context, source_type: "httpd_t", target_type: "httpd_t", target_class: "capability",
      permissions: ["net_admin"], executable: "/usr/sbin/httpd", details: { "permissive" => true })
    described_class.call(double(normalized_denial: denial, raw_event: double(raw_audit_records: records)))
  end

  it "explains a retained socket-buffer request without assigning a workload purpose or changing stored evidence" do
    records = [avc, syscall]
    result = guidance(records)
    expect(result[:explanation]).to include("administrator privileges", "privileged socket settings")
    expect(result[:evidence]).to include("x86-64 setsockopt", "SO_SNDBUFFORCE", "send buffer", "memory for outgoing data")
    expect(result[:hypothesis]).to include("may be tuning socket buffers", "startup configuration")
    expect(result[:outcome]).to include("permissive mode", "system call succeeded")
    expect(records).to eq([avc, syscall])
  end

  it "distinguishes receive-buffer requests and failed system calls" do
    result = guidance([avc, syscall.sub("a2=20", "a2=21").sub("success=yes", "success=no")])
    expect(result[:evidence]).to include("SO_RCVBUFFORCE", "receive buffer")
    expect(result[:outcome]).to eq("The associated system call failed.")
  end

  it "requires matching architecture, syscall and hexadecimal arguments for socket-buffer interpretation" do
    [syscall.sub("arch=c000003e", "arch=40000003"), syscall.sub("arch=c000003e ", ""),
      syscall.sub("syscall=54", "syscall=16"), syscall.sub("a1=1", "a1=6"),
      syscall.sub("a2=20", "a2=32"), syscall.sub("a2=20", "a2=garbage"), syscall.sub("a2=20 ", "")].each do |record|
      result = guidance([avc, record])
      expect(result).to have_key(:explanation)
      expect(result).not_to have_key(:hypothesis)
      expect(result).not_to have_key(:evidence)
    end
  end

  it "does not borrow syscall interpretation or outcomes from ambiguous or mismatched records" do
    [[avc, avc, syscall], [avc, syscall, syscall], ["type=AVC denied { net_admin }", syscall],
      [avc, syscall.sub("pid=2012", "pid=999")], [avc, syscall.sub("exe=\"/usr/sbin/httpd\"", "exe=\"/bin/other\"")],
      [avc, syscall.sub("subj=#{context}", "subj=system_u:system_r:other_t:s0")], []].each do |records|
      expect(guidance(records).keys).to eq([:explanation])
    end
  end
end
