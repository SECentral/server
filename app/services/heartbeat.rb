class Heartbeat
  def self.call(organization:, payload:)
    new(organization, payload).call
  end

  def initialize(organization, payload)
    @organization = organization
    @payload = payload
  end

  def call
    validate!
    now = Time.current
    observed_at = Time.iso8601(@payload.fetch("host_observed_at"))
    stale_policy_state = false
    ActiveRecord::Base.transaction do
      host = Host.find_for_ingestion!(@organization, @payload.dig("host", "id"))
      host.with_lock do
        host.hostname = @payload.dig("host", "hostname")
        host.boot_id = @payload.dig("host", "boot_id")
        host.last_seen_at = now
        host.save!
        installation = host.agent_installations.find_or_create_by!(organization: @organization) do |record|
          record.name = host.external_id
        end
        installation.update!(last_seen_at: now, agent_version: @payload.dig("agent", "version"))
        stale_policy_state = host.raw_events.state_transitions.where(boot_id: @payload.dig("host", "boot_id"))
          .where("audit_timestamp >= ?", observed_at).exists?
        unless stale_policy_state
          snapshot = host.host_snapshots.find_or_create_by!(details: @payload.fetch("host"))
          observation = host.host_snapshot_observations.first
          if observation&.host_snapshot == snapshot
            observation.update!(last_observed_at: observed_at, last_received_at: now)
          else
            host.host_snapshot_observations.create!(
              host_snapshot: snapshot,
              agent_installation: installation,
              first_observed_at: observed_at,
              last_observed_at: observed_at,
              first_received_at: now,
              last_received_at: now
            )
          end
        end
      end
    end
    return {} if stale_policy_state

    identity = @payload.dig("host", "selinux", "policy_identity")
    return {} unless identity.to_s.match?(PolicyArtifact::IDENTITY_FORMAT)

    PolicyArtifact.exists?(policy_identity: identity) ? {} : { policy_artifact_required: true, policy_identity: identity }
  end

  class InvalidRequest < StandardError
    attr_reader :details

    def initialize(details)
      @details = details
      super("heartbeat validation failed")
    end
  end

  private

  def validate!
    details = []
    details << detail("schema_version", "unsupported_schema_version") unless @payload.is_a?(Hash) && @payload["schema_version"] == 2
    details << detail("agent.version", "required") if blank?(@payload.dig("agent", "version"))
    details << detail("host.id", "required") if blank?(@payload.dig("host", "id"))
    details << detail("host.boot_id", "required") if blank?(@payload.dig("host", "boot_id"))
    details << detail("host_observed_at", "required") if blank?(@payload["host_observed_at"])
    details << detail("host_observed_at", "invalid_timestamp") if !blank?(@payload["host_observed_at"]) && !timestamp?(@payload["host_observed_at"])
    enforcement = @payload.dig("host", "selinux", "enforcement")
    details << detail("host.selinux.enforcement", "unknown_enforcement") unless %w[enforcing permissive disabled unknown].include?(enforcement)
    raise InvalidRequest, details if details.any?
  end

  def detail(path, code)
    { "path" => path, "code" => code }
  end

  def blank?(value)
    value.nil? || value == ""
  end

  def timestamp?(value)
    Time.iso8601(value.to_s)
    true
  rescue ArgumentError
    false
  end
end
