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
  end

  it "escapes shell-special characters as one literal argument" do
    target = "/var/www/html/a 'quoted';$(touch bad)*.txt"
    result = described_class.call(issue, paths: [target])
    expect(Shellwords.split(result[:commands].first[:command])).to eq(["matchpathcon", "--", target])
    expect(Shellwords.split(result[:commands][1][:command])).to eq(["restorecon", "-v", "--", target])
  end

  it "rejects relative, noncanonical, control-character and directory paths" do
    ["file.txt", "/var/www/../home/file", "/var/www/html/a\nfile", "/var/www/html/", "/etc"].each do |target|
      expect(described_class.call(issue, paths: [target])).to be_nil
    end
    allow(issue).to receive(:target_class).and_return("dir")
    expect(described_class.call(issue, paths: [path])).to be_nil
  end
end
