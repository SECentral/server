# SECentral Server

The SECentral server receives SELinux events and host checkpoints from agents,
preserves raw evidence, and provides an operator API and web interface for
investigating fleet activity.

It normalizes and groups events into issues, shows host configuration and
SELinux activity, and provides evidence-backed analysis and resolution
workflows. Operators can create and export policy drafts for review; SECentral
does not automatically deploy policy changes.

The Rails application serves a React + TypeScript SPA. PostgreSQL stores server
data. See [TEST.md](TEST.md) for development and test instructions.

See [Contributing](CONTRIBUTING.md) for feedback and contribution guidelines.

## Self-hosted deployment

Follow the [Quick Start](docs/quick-start.md) to deploy the published Quay image
with Podman/Compose, PostgreSQL and automatic HTTPS, install an agent from COPR,
and investigate a real denial. It also covers backups, upgrades, troubleshooting
and evaluation cleanup. The server image is available for Linux amd64.

## Current capabilities

Agents can submit authenticated events, heartbeats, expected-context
observations, and requested policy artifacts. The server persists raw event
evidence, normalizes and groups occurrences into issues, and exposes operator
views for issues, hosts, SELinux activity, configuration, catalogs, analysis,
and resolution intent. Policy drafts can be staged and exported for review.

Catalog names and active/archive lifecycle are managed separately from immutable
revision content. See [Managing catalogs](docs/catalog-lifecycle.md)
for validated upload/preview/confirmation, renaming, archiving, automatic and
temporary explicit reference selection and API usage. CLI and browser imports
share validation and immutable revision semantics; reimport preserves existing
names/archive state.

The [catalog source contract](catalogs/README.md) supports manual, pinned artifact
acquisition and immutable updates for separately licensed, SECentral-reviewed
distribution references; no catalog is automatically imported.
Successful imports record bounded semantic comparison reports when a unique
same-context basis exists.

Human-facing access uses one configured operator account. User management,
RBAC, OIDC, and tenant authorization are not currently provided.

## Operator authentication

Set `ADMIN_USERNAME` and `ADMIN_PASSWORD_DIGEST` to enable the human-facing
login. The password value is never configured directly; create a bcrypt digest
for the chosen password as described in the [Quick Start](docs/quick-start.md).

Production must provide both operator variables. Missing or invalid credentials fail
closed and do not expose operator routes. Agent bearer authentication remains
separate and continues to protect the ingestion endpoints.

## Ingestion authentication

Production must set `SECENTRAL_INGESTION_KEY`. Every agent uses that same value
as `Authorization: Bearer <key>` for events, heartbeats, expected-context
observations, and requested policy artifacts. It authorizes only those agent
ingestion endpoints, not operator or read APIs. The deployment has exactly one
organization; ingestion fails clearly if that invariant is absent. First startup
prepares the database and seeds that organization before agents connect;
ingestion itself never creates or selects an organization.

## Licensing

SECentral application/source code is licensed under [MIT](LICENSE).
Distributed SELinux catalog artifacts under `catalogs/` are **GPL-2.0-or-later
unless otherwise noted**; this does not relicense the MIT application. See the
[catalog contract and attribution](catalogs/README.md) and shared
[license text](catalogs/LICENSES/GPL-2.0-or-later.txt).
