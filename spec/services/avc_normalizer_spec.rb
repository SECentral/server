require "rails_helper"

RSpec.describe AvcNormalizer do
  let(:network_fixture) { JSON.parse(File.read(Rails.root.join("spec/fixtures/contracts/network-evidence.json"))) }
  let(:process_fixture) { JSON.parse(File.read(Rails.root.join("spec/fixtures/contracts/process-evidence.json"))) }
  let(:avc) do
    'audit(100.000:7): avc:  denied  { read open read } for pid=10 comm="httpd" exe="/usr/sbin/httpd" path="/srv/www/index.html" scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:default_t:s0 tclass=file permissive=0'
  end

  it "normalizes AVC fields and preserves occurrence attributes" do
    result = described_class.call([avc]).first

    expect(result).to include(
      status: "ok",
      source_context: "system_u:system_r:httpd_t:s0",
      source_type: "httpd_t",
      target_context: "system_u:object_r:default_t:s0",
      target_type: "default_t",
      target_class: "file",
      permissions: %w[read open],
      permissive: false,
      command: "httpd",
      executable: "/usr/sbin/httpd",
      target_paths: ["/srv/www/index.html"]
    )
  end

  it "normalizes syscall outcome evidence" do
    result = described_class.call([avc, 'type=SYSCALL syscall=42 success=no exit=-13']).first

    expect(result[:syscall_evidence]).to include("syscall" => "42", "success" => "no", "exit" => "-13")
  end

  it "normalizes permissive AVC state without discarding the raw field" do
    result = described_class.call([avc.sub("permissive=0", "permissive=1")]).first

    expect(result[:permissive]).to be(true)
  end

  it "accepts USER_AVC records and combines raw records" do
    records = [
      'audit(100.000:7): user_avc: denied { read } for scontext=system_u:system_r:httpd_t:s0',
      'tcontext=system_u:object_r:default_t:s0 tclass=file'
    ]

    expect(described_class.call(records).first).to include(status: "ok", permissions: ["read"])
  end

  it "returns an explicit ungroupable result for incomplete AVC data" do
    result = described_class.call(['avc: denied { read } for scontext=system_u:system_r:httpd_t:s0']).first

    expect(result[:status]).to eq("ungroupable")
    expect(result[:missing]).to include("tcontext", "tclass")
  end

  it "does not discard records with unrelated syntax" do
    result = described_class.call(["type=PATH name=foo", avc]).first

    expect(result[:status]).to eq("ok")
    expect(result[:target_paths]).to eq(["/srv/www/index.html"])
    expect(result[:target_evidence]).to eq(path_fields: ["/srv/www/index.html"], filesystem_paths: ["/srv/www/index.html"], object_names: ["foo"])
  end

  it "keeps AVC identity fields when supporting records follow the AVC" do
    result = described_class.call([
      avc,
      'audit(100.000:7): syscall=257 comm="httpd" exe="/usr/sbin/httpd"',
      'audit(100.000:7): eoe='
    ]).first

    expect(result).to include(source_type: "httpd_t", target_type: "default_t", target_class: "file")
  end

  it "preserves paths from multiple supporting records" do
    result = described_class.call([
      "type=AVC avc: denied { read } scontext=u:r:httpd_t:s0 tcontext=u:object_r:default_t:s0 tclass=file",
      "type=PATH name=/a",
      "type=PATH name=/b"
    ]).first

    expect(result[:target_paths]).to eq(%w[/a /b])
    expect(result[:target_evidence]).to eq(path_fields: [], filesystem_paths: %w[/a /b], object_names: %w[/a /b])
  end

  it "accepts absolute names from PATH records but does not resolve relative names" do
    result = described_class.call([
      "avc: denied { read } scontext=u:r:httpd_t:s0 tcontext=u:object_r:default_t:s0 tclass=file",
      "type=PATH name=/var/www/cgi-bin/helper.sh item=0 nametype=NORMAL",
      "type=PATH name=./helper.sh item=1 nametype=NORMAL"
    ]).first

    expect(result[:target_paths]).to eq(["/var/www/cgi-bin/helper.sh"])
    expect(result[:target_evidence]).to eq(path_fields: [], filesystem_paths: ["/var/www/cgi-bin/helper.sh"], object_names: ["/var/www/cgi-bin/helper.sh", "./helper.sh"])
  end

  it "keeps identical path and name values in separate evidence categories" do
    result = described_class.call([
      "avc: denied { read } path=lock name=lock scontext=u:r:httpd_t:s0 tcontext=u:object_r:default_t:s0 tclass=file"
    ]).first

    expect(result[:target_evidence]).to eq(path_fields: ["lock"], filesystem_paths: [], object_names: ["lock"])
  end

  it "keeps non-filesystem path fields but does not classify them as filesystem paths" do
    result = described_class.call([
      "avc: denied { read } path=user:[4026533377] scontext=u:r:httpd_t:s0 tcontext=u:object_r:nsfs_t:s0 tclass=file"
    ]).first

    expect(result[:target_evidence]).to eq(path_fields: ["user:[4026533377]"], filesystem_paths: [], object_names: [])
  end

  it "marks malformed contexts ungroupable" do
    result = described_class.call([
      "avc: denied { read } scontext=garbage tcontext=u:object_r:default_t:s0 tclass=file"
    ]).first

    expect(result).to include(status: "ungroupable")
    expect(result[:missing]).to include("source_type")
  end

  it "normalizes captured network evidence without inference" do
    result = described_class.call([network_fixture.fetch("cases").first.fetch("payload")]).first

    expect(result[:network_evidence]).to eq(
      "dest_fields" => ["10.0.0.8"], "dport_fields" => ["443"], "lport_fields" => ["52144"], "bind_port_fields" => [],
      "proto_fields" => ["tcp"], "operations" => ["name_connect"]
    )
  end

  it "retains socket operations without inventing endpoint evidence" do
    result = described_class.call([network_fixture.fetch("cases").last.fetch("payload")]).first

    expect(result[:network_evidence]).to eq(
      "dest_fields" => [], "dport_fields" => [], "lport_fields" => [], "proto_fields" => [], "bind_port_fields" => [], "operations" => ["name_connect"]
    )
  end

  it "normalizes a bind source port only for name_bind" do
    result = described_class.call(["avc: denied { name_bind } src=12345 scontext=u:r:httpd_t:s0 tcontext=system_u:object_r:unreserved_port_t:s0 tclass=tcp_socket"]).first

    expect(result[:network_evidence]["bind_port_fields"]).to eq(["12345"])
    expect(result[:evidence_provenance]).to include(hash_including("kind" => "bind_port", "value" => "12345"))
  end

  it "does not interpret src as a bind port for other permissions" do
    result = described_class.call(["avc: denied { name_connect } src=12345 scontext=u:r:httpd_t:s0 tcontext=system_u:object_r:unreserved_port_t:s0 tclass=tcp_socket"]).first

    expect(result[:network_evidence]["bind_port_fields"]).to eq([])
    expect(result[:evidence_provenance]).not_to include(hash_including("kind" => "bind_port"))
  end

  it "normalizes captured process evidence without inferring a transition" do
    result = described_class.call([process_fixture.fetch("cases").first.fetch("payload")]).first

    expect(result[:process_evidence]).to eq(
      "pids" => ["1842"], "commands" => ["worker"], "executables" => ["/usr/local/bin/worker"], "source_contexts" => ["u:r:worker_t:s0"]
    )
  end

  it "retains a PID without inventing missing process identity" do
    result = described_class.call([process_fixture.fetch("cases").last.fetch("payload")]).first

    expect(result[:process_evidence]).to eq(
      "pids" => ["1842"], "commands" => [], "executables" => [], "source_contexts" => ["u:r:worker_t:s0"]
    )
  end

  it "records provenance for values supplied by each raw record" do
    records = [
      double(payload: "avc: denied { read } scontext=u:r:httpd_t:s0 tcontext=u:object_r:default_t:s0 tclass=file", type_name: "AVC", position: 0),
      double(payload: 'type=SYSCALL pid=42 comm="httpd" exe="/usr/sbin/httpd"', type_name: "SYSCALL", position: 1),
      double(payload: 'type=PATH name="/srv/www/index.html"', type_name: "PATH", position: 2)
    ]

    provenance = described_class.call(records).first.fetch(:evidence_provenance)

    expect(provenance).to include(
      { "kind" => "executable", "value" => "/usr/sbin/httpd", "source_record_type" => "SYSCALL", "source_record_position" => 1, "temporal_scope" => "occurrence", "certainty" => "observed" },
      { "kind" => "object_name", "value" => "/srv/www/index.html", "source_record_type" => "PATH", "source_record_position" => 2, "temporal_scope" => "occurrence", "certainty" => "observed" }
    )
  end

  it "preserves conflicting values with their source positions" do
    records = [
      double(payload: "avc: denied { read } scontext=u:r:httpd_t:s0 tcontext=u:object_r:default_t:s0 tclass=file", type_name: "AVC", position: 0),
      double(payload: 'type=SYSCALL exe="/usr/sbin/httpd"', type_name: "SYSCALL", position: 1),
      double(payload: 'type=SYSCALL exe="/usr/local/bin/httpd-wrapper"', type_name: "SYSCALL", position: 3)
    ]

    provenance = described_class.call(records).first.fetch(:evidence_provenance)

    expect(provenance).to include(
      { "kind" => "executable", "value" => "/usr/sbin/httpd", "source_record_type" => "SYSCALL", "source_record_position" => 1, "temporal_scope" => "occurrence", "certainty" => "observed" },
      { "kind" => "executable", "value" => "/usr/local/bin/httpd-wrapper", "source_record_type" => "SYSCALL", "source_record_position" => 3, "temporal_scope" => "occurrence", "certainty" => "observed" }
    )
  end
end
