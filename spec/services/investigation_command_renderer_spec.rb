require "rails_helper"

RSpec.describe InvestigationCommandRenderer do
  it "keeps the full policy listing so range entries are not missed" do
    expect(described_class.call(kind: :port_classification, protocol: "tcp", port: 12345)).to eq("semanage port -l")
    expect(described_class.call(kind: :port_local_classification, protocol: "tcp", port: 12345)).to eq("semanage port -l -C")
  end

  it "filters listeners by the exact local port and protocol" do
    { "tcp" => "-ltnp", "udp" => "-lunp" }.each do |protocol, flags|
      command = described_class.call(kind: :socket_listeners, protocol: protocol, port: 12345, operation: "name_bind")
      expect(Shellwords.split(command)).to eq(["ss", flags, "sport = :12345"])
    end
  end

  it "does not turn a remote connect endpoint into a local listener check" do
    expect(described_class.call(kind: :socket_listeners, protocol: "tcp", port: 443, operation: "name_connect")).to be_nil
  end

  it "validates policy query fields before rendering a read-only search" do
    check = { kind: :port_policy_alternatives, source_type: "httpd_t", object_class: "tcp_socket", operation: "name_bind" }
    expect(described_class.call(check)).to eq("sesearch -A -s httpd_t -c tcp_socket -p name_bind -C")
    [{ source_type: "httpd_t;id" }, { object_class: "file" }, { operation: "name_bind;id" }].each do |invalid|
      expect(described_class.call(check.merge(invalid))).to be_nil
    end
  end

  it "rejects invalid endpoint fields before rendering commands" do
    [{ protocol: "sctp", port: 12345 }, { protocol: "tcp;id", port: 12345 },
     { protocol: "tcp", port: "12345;id" }, { protocol: "tcp", port: 0 },
     { protocol: "tcp", port: 65_536 }, { protocol: "tcp", port: nil }].each do |endpoint|
      %i[port_classification port_local_classification socket_listeners].each do |kind|
        expect(described_class.call(endpoint.merge(kind: kind, operation: "name_bind"))).to be_nil
      end
    end
  end
end
