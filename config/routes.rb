Rails.application.routes.draw do
  # Overview serves the SPA shell (plan 0053 Phase 5); the React app owns `/`.
  root to: "spa#index"

  # Agent ingestion routes stay isolated behind bearer authentication.
  post "/api/v1/events", to: "events#create"
  post "/api/v1/heartbeat", to: "heartbeats#create"
  post "/api/v1/expected-context-observations", to: "expected_context_observations#create"
  put "/api/v1/policy-artifacts/:policy_identity", to: "policy_artifacts#create"

  # Versioned operator API (plan 0053); controllers live under Api::V1.
  namespace :api do
    namespace :v1 do
      get "system", to: "system#show"
      get "sessions", to: "sessions#show"
      post "sessions", to: "sessions#create"
      delete "sessions", to: "sessions#destroy"
      get "issues", to: "issues#index"
      get "issues/:id", to: "issues#show"
      patch "issues/:id/status", to: "issues#update_status"
      patch "issues/:id/disposition", to: "issues#update_disposition"
      get "issues/:id/occurrences", to: "issue_occurrences#index"
      get "issues/:id/occurrences/:occurrence_id", to: "issue_occurrences#show"
      get "issues/:id/analysis", to: "issue_analysis#show"
      get "issues/:id/resolutions", to: "issue_resolutions#show"
      patch "issues/:id/resolution-intent", to: "issue_resolutions#update"
      delete "issues/:id/resolution-intent", to: "issue_resolutions#destroy"
      get "policy-drafts", to: "policy_drafts#index"
      post "policy-drafts", to: "policy_drafts#create"
      post "policy-drafts/:id/entries", to: "policy_drafts#stage"
      delete "policy-drafts/:id/entries/:entry_id", to: "policy_drafts#destroy_entry"
      post "policy-drafts/:id/export", to: "policy_drafts#export"
      get "ungroupable-events", to: "ungroupable_events#index"
      get "hosts", to: "hosts#index"
      get "hosts/:id", to: "hosts#show"
      get "hosts/:id/occurrences", to: "host_occurrences#index"
      get "hosts/:id/selinux-activity", to: "host_selinux_activities#index"
      get "hosts/:id/selinux-activity/:event_id", to: "host_selinux_activities#show"
      get "hosts/:id/configuration", to: "host_configurations#show"
      get "configuration", to: "configurations#show"
      get "catalogs", to: "catalogs#index"
      get "catalogs/:id", to: "catalogs#show"
      get "overview", to: "overview#show"
    end
  end

  # Health check for load balancers and uptime monitors.
  get "up" => "rails/health#show", as: :rails_health_check

  # Retired /dashboard paths remain unrouted instead of showing the SPA fallback.
  # SPA catch-all: every other path is served to the React app.
  get "(*path)" => "spa#index",
      constraints: ->(request) { request.path !~ %r{\A/(api|up|dashboard)(/|\z)} }
end
