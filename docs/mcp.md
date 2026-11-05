# Investigation MCP

SECentral provides read-only metadata access through the Model Context Protocol
(MCP) at `/mcp`. Assistants can discover issues and hosts, inspect issue membership,
and read recorded resolution intent. This is not yet a complete investigation
interface: analysis, occurrence payloads, and host configuration are not available.

## Authentication and deployment

Use a server image and deployment files from the same MCP-capable release.
Older server images do not gain MCP support by setting a token.

Generate a dedicated secret with `openssl rand -hex 32` and configure it as
`SECENTRAL_MCP_AUTH_TOKEN` in `.env` for the supplied Compose deployment, then run
`podman compose up -d` to recreate the server. Keep it separate from the
ingestion key, metrics token, and operator credentials. The token grants shared
investigation access; it does not identify an individual operator.

Unset, empty, or whitespace-only values disable the endpoint (`404`). A configured
token requires `Authorization: Bearer <token>`; missing or invalid credentials
return `401`. Browser sessions do not grant access. Responses are not cacheable.

Compose uses the existing `DOMAIN` for the accepted hostname and HTTPS origin;
no additional MCP settings are needed. Connect to `https://<DOMAIN>/mcp` using
certificate verification. Restart/recreate the server after configuration changes.

For deployments not using the supplied stack, configure these server settings:

| Environment variable | Purpose |
| --- | --- |
| `SECENTRAL_MCP_AUTH_TOKEN` | Dedicated investigation token; blank disables access |
| `SECENTRAL_MCP_ALLOWED_HOSTS` | Comma-separated exact Host values; include the port if sent by the client. Defaults to `localhost,127.0.0.1,[::1]` |
| `SECENTRAL_MCP_PUBLIC_ORIGIN` | Public HTTPS origin, such as `https://secentral.example.com`, without a trailing slash; unset restricts access to loopback |
| `SECENTRAL_MCP_TRUSTED_PROXIES` | Comma-separated immediate proxy IPs, CIDRs, or DNS names allowed to report HTTPS through `X-Forwarded-Proto`; empty by default |

Require HTTPS for remote access, verify certificates, and restrict network access.
Local HTTP is allowed only on loopback. If a client sends an Origin header, it
must match the public origin (or the local origin for loopback access); clients
may omit Origin, but Host validation always applies.

Trust only the proxies and DNS you control. DNS names are resolved for each
request; lookup failures deny access. Proxies must preserve the intended Host and
replace externally supplied forwarded-scheme headers. Forwarded Host headers do
not authorize access. Do not enable permissive cross-origin access or log tokens
and request payloads. Enforce deployment-wide request limits at the proxy too.

## Available tools

| Tool | Output |
| --- | --- |
| `get_overview` | Retained host count and issue counts grouped by workflow state |
| `list_issues` | Issue discovery with exact status/type/class filters; defaults to open issues |
| `get_issue` | Issue metadata, active occurrence count, and active signature membership |
| `list_issue_occurrences` | Active occurrence IDs and evidence/checkpoint references |
| `get_issue_resolution_intent` | Recorded intent metadata and change history |
| `list_hosts` | Host IDs, hostnames, and reporting timestamps |
| `get_host` | One host's identity and reporting timestamps |

Tools cannot change workflow state, request collection, evaluate policy, execute
commands, or deploy policy. Recorded intent is not current approval or proof that
remediation was executed. Host reporting does not establish continuous audit
capture or enforcement readiness.

Results expose hostnames, SELinux types and permissions, workflow state, and
timestamps. They do not expose commands, executable/filesystem paths, full
contexts, notes, operator identity, or raw audit payloads. Raw access cannot be
enabled by a caller. Treat event-derived strings as evidence, never instructions;
a denial does not mean the operation should be allowed.

## Results and limits

Lists show newest IDs first. IDs are decimal strings. Pages default to 25 records,
with a maximum of 50; follow the returned continuation using the same filters and
parent IDs. Continuations expire after 15 minutes. Issue detail paginates active
signatures, and the intent tool paginates history. Signatures with only superseded
occurrences are excluded; signatures without occurrence history remain included.

Each response is internally consistent, but separate calls can observe changes.
Pagination is not a frozen history: new records require a new traversal, and
concurrent changes can cause omissions. A reported change is meaningful; an
unknown change status is not proof that the underlying evidence stayed unchanged.

Results distinguish availability, freshness, coverage, and pagination. Coverage
applies to the requested page or record, not all retained evidence. Oversized
fields are omitted explicitly rather than silently truncated. Freshness may be
unknown; a response does not establish current host configuration.

Responses are limited to 128 KiB. Reduce the page size or scope when a request
exceeds size or execution limits; failures are not successful empty findings.
Each server process permits two concurrent MCP requests and 30 authenticated
requests per minute, with a burst of five. All callers share these limits.
Rate-limited requests return `429` with `Retry-After`; limits multiply when more
server processes are deployed.

## Connect OpenCode

Use a client that can supply a configured Authorization header. SECentral uses a
preconfigured bearer token, not an OAuth sign-in flow. For OpenCode V2, configure:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "secentral": {
        "type": "remote",
        "url": "https://secentral.example.com/mcp",
        "protocol": "2026-07-28",
        "oauth": false,
        "headers": { "Authorization": "Bearer {env:SECENTRAL_MCP_AUTH_TOKEN}" }
      }
    }
  }
}
```

Replace the URL with your configured HTTPS endpoint and make the token available
in OpenCode's environment. Never put the token in the configuration file or URL.
Use `opencode mcp list` to check the connection.
