require "rails_helper"
require_relative "../support/port_resolution_fixtures"

RSpec.describe "Superseded occurrence evidence", type: :request do
  include PortResolutionFixtures

  around do |example|
    ActiveRecord::Base.transaction do
      example.run
      raise ActiveRecord::Rollback
    end
  end

  it "retains historical detail URLs without listing the old interpretation or supplying guidance" do
    issue, occurrence, host, = port_fixture
    occurrence.update!(superseded_at: Time.current)
    issue.update!(occurrences_count: 0)
    sign_in_operator

    ["/api/v1/hosts/#{host.id}/occurrences/#{occurrence.id}", "/api/v1/issues/#{issue.id}/occurrences/#{occurrence.id}"].each do |url|
      get url
      expect(response).to have_http_status(:ok)
      body = JSON.parse(response.body)
      expect(body["superseded_at"]).to be_present
      expect(body["guidance"]).to be_nil
      expect(body.dig("raw_event", "id")).to eq(occurrence.raw_event_id)
    end
    get "/api/v1/issues/#{issue.id}/occurrences", params: { view: "summary" }
    expect(JSON.parse(response.body).fetch("occurrences")).to be_empty
    get "/api/v1/hosts/#{host.id}/occurrences"
    expect(JSON.parse(response.body).fetch("occurrences")).to be_empty
    expect(Occurrence.count).to eq(0)
    expect(Occurrence.unscoped.count).to eq(1)
  end
end
