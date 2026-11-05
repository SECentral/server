module McpInvestigation
  class ProtocolServer < MCP::Server
    # The SDK's protocol_version setting is a fallback, not a supported-version
    # restriction: it otherwise echoes older versions we do not serve. Keep all
    # validation/handshake handling in the SDK while offering our legacy revision.
    def init(arguments, session: nil)
      validate_initialize_params!(arguments)
      super(arguments.merge(protocolVersion: "2025-11-25"), session: session)
    end
  end
end
