require "rails_helper"

RSpec.describe SelinuxExplanation do
  it "keeps an unavailable evaluator visible instead of guessing" do
    issue = instance_double(Issue, source_type: "httpd_t", target_type: "user_home_t", target_class: "file", permissions: ["read"], occurrences_count: 1, occurrences: [])

    result = described_class.call(issue, intelligence: { paths: ["/var/www/index.html"], contexts: [] })

    expect(result).to include(evaluated_mechanism: nil, confidence_band: "low")
    expect(result).to include(policy_analysis: include(status: "unavailable"))
    expect(result[:missing_evidence]).to include("no exact reusable policy facts are available")
  end
end
