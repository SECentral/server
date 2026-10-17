require "rails_helper"

RSpec.describe IssueLabelingGuidance do
  let(:issue) { instance_double(Issue, source_type: "httpd_t", target_type: "user_home_t", target_class: "file", permissions: %w[read open]) }
  let(:path) { "/var/www/html/file.txt" }

  it "suppresses conventions contradicted by an eligible configured label, including custom mappings" do
    %w[user_home_t custom_web_t].each do |type|
      observation = { "path" => path, "expected_context" => "system_u:object_r:#{type}:s0" }
      expect(described_class.call(issue, paths: [path], observations: [observation])).to be_nil
    end
    expect(described_class.call(issue, paths: [path], observations: [
      { "path" => path, "expected_context" => "system_u:object_r:httpd_sys_content_t:s0" }
    ])).to include(conventional_type: "httpd_sys_content_t")
  end

  it "keeps targeted checks but suppresses recursion at broad system roots" do
    %w[/etc/shadow /srv/data /var/www/file.txt].each do |target|
      result = described_class.call(issue, paths: [target])
      expect(result[:recursive_directory]).to be_nil
      expect(result[:commands].map { |item| item[:action] }).to eq(%w[inspect restore_targeted])
    end
  end

  it "reports a deterministic representative and exact retained-path scope without inventing occurrence coverage" do
    paths = ["/var/www/other/z", "/var/www/html/later.txt", "/var/www/html/immediate.txt"]
    result = described_class.call(issue, paths: paths)
    expect(result).to include(path: paths.last, path_count: 3, recursive_directory: "/var/www/html", recursive_path_count: 2)
    expect(result).not_to have_key(:expected_type)
    expect(result).not_to have_key(:occurrence_count)
    expect(described_class.call(issue, paths: paths.reverse + [paths.last])).to eq(result)
  end

  it "escapes shell-special characters as one literal argument" do
    target = "/var/www/html/a 'quoted';$(touch bad)*.txt"
    result = described_class.call(issue, paths: [target])
    expect(Shellwords.split(result[:commands].first[:command])).to eq(["matchpathcon", "--", target])
    expect(Shellwords.split(result[:commands][1][:command])).to eq(["restorecon", "-v", "--", target])
    expect(Shellwords.split(result[:commands][2][:command])).to eq(["restorecon", "-Rv", "--", "/var/www/html"])
  end

  it "rejects relative, noncanonical, control-character and directory paths" do
    ["file.txt", "/var/www/../home/file", "/var/www/html/a\nfile", "/var/www/html/a\0file", "/var/www/html/a\rfile", "/var/www/html/", "/etc", "/var/www-other/file", "/home/file"].each do |target|
      expect(described_class.call(issue, paths: [target])).to be_nil
    end
    allow(issue).to receive(:target_class).and_return("dir")
    expect(described_class.call(issue, paths: [path])).to be_nil
  end

  it "restricts labels, file classes and permissions while allowing each documented permission" do
    %w[read open write getattr].each do |permission|
      allow(issue).to receive(:permissions).and_return([permission])
      expect(described_class.call(issue, paths: [path])).not_to be_nil
    end
    %w[execute entrypoint unlink].each do |permission|
      allow(issue).to receive(:permissions).and_return([permission])
      expect(described_class.call(issue, paths: [path])).to be_nil
    end
    allow(issue).to receive(:permissions).and_return(["read"])
    allow(issue).to receive(:target_type).and_return("httpd_sys_content_t")
    expect(described_class.call(issue, paths: [path])).to be_nil
    allow(issue).to receive(:target_type).and_return("default_t")
    expect(described_class.call(issue, paths: [path])).to include(observed_type: "default_t")
    %w[dir lnk_file tcp_socket].each do |object_class|
      allow(issue).to receive(:target_class).and_return(object_class)
      expect(described_class.call(issue, paths: [path])).to be_nil
    end
  end

  it "does not invent conventions for other domains or directories" do
    %w[/srv/app/data /etc/app/config].each do |target|
      expect(described_class.call(issue, paths: [target])).to include(conventional_type: nil)
    end
    allow(issue).to receive(:source_type).and_return("custom_t")
    expect(described_class.call(issue, paths: [path])).to include(conventional_type: nil)
  end

  it "suppresses conflicting eligible observations even without a named convention" do
    target = "/srv/app/data"
    observations = %w[custom_a_t custom_b_t].map do |type|
      { "path" => target, "expected_context" => "system_u:object_r:#{type}:s0" }
    end
    expect(described_class.call(issue, paths: [target], observations: observations)).to be_nil
    expect(described_class.call(issue, paths: [target], observations: observations.reverse)).to be_nil
    expect(described_class.call(issue, paths: [path], observations: observations)).not_to be_nil
  end
end
