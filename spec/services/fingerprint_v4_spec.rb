require "rails_helper"

RSpec.describe FingerprintV4 do
  it "uses a frozen relationship identity independent of permissions, paths and enforcement" do
    denial = { source_type: "httpd_t", target_type: "user_home_t", target_class: "file", permissions: ["read"] }
    fingerprint = { version: 4, digest: "52d363f98706f0c55833f5108b2efddcecbfc140153e632a3831c4d30e9cf9be" }
    expect(described_class.call(denial)).to eq(fingerprint)
    expect(described_class.call(denial.merge(permissions: %w[open read], path: "/other", permissive: true))).to eq(fingerprint)
    expect(described_class.call(denial.merge(target_class: "dir"))).not_to eq(fingerprint)
    expect(described_class.call(denial.merge(target_type: "httpd_sys_content_t"))).not_to eq(fingerprint)
    expect(described_class.call(denial.merge(source_type: "nginx_t"))).not_to eq(fingerprint)
  end
end
