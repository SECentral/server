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

The Compose deployment uses the published `quay.io/secentral/server:0.0.3` image
with PostgreSQL and automatic HTTPS. Podman and `podman-compose` are required.
The server image is currently available for Linux amd64.

1. Point a public DNS name at the host and allow inbound TCP ports 80 and 443
   (and UDP 443 for HTTP/3).
2. Copy `.env.example` to `.env`, then set `DOMAIN`, `SECRET_KEY_BASE`,
   `SECENTRAL_SERVER_DATABASE_PASSWORD`, and `SECENTRAL_INGESTION_KEY` to
   unique generated values. For random values, use `openssl rand -hex 32`.
3. Set `ADMIN_USERNAME` and `ADMIN_PASSWORD_DIGEST`. Generate a bcrypt digest
   for your chosen operator password with the published image:

   ```sh
   read -rsp 'Operator password: ' ADMIN_PASSWORD; printf '\n'
   printf '%s' "$ADMIN_PASSWORD" | podman run --rm -i --entrypoint bundle \
     quay.io/secentral/server:0.0.3 exec ruby -rbcrypt \
     -e 'puts BCrypt::Password.create(STDIN.read)'
   unset ADMIN_PASSWORD
   ```

   Put the printed digest in `.env` as `ADMIN_PASSWORD_DIGEST`, enclosed in single
   quotes so Compose preserves its `$` characters.
4. Start the services with `podman-compose up -d`.
5. Open `https://<DOMAIN>` and sign in with the configured operator account.

Keep `.env` private and back up the PostgreSQL volume. The Compose deployment
uses Caddy to obtain and renew HTTPS certificates. It publishes the Rails app
through Caddy only; PostgreSQL is not published to the host. `podman-compose down`
preserves the database volume; `podman-compose down -v` deletes it.

Agent hosts must use the same `SECENTRAL_INGESTION_KEY` value for bearer
authentication.

To upgrade, back up the database, update the server image version in
`compose.yaml`, then run `podman-compose pull server` and `podman-compose up -d`.
The application entrypoint prepares the database and applies migrations; reverting
the image does not undo those migrations. For a database backup:

```sh
podman-compose exec -T db pg_dump -U secentral_server secentral_server_production > secentral-backup.sql
```

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
for the chosen password as described in the self-hosted deployment instructions.

Production must provide both operator variables. Missing or invalid credentials fail
closed and do not expose operator routes. Agent bearer authentication remains
separate and continues to protect the ingestion endpoints.

## Ingestion authentication

Production must set `SECENTRAL_INGESTION_KEY`. Every agent uses that same value
as `Authorization: Bearer <key>` for events, heartbeats, expected-context
observations, and requested policy artifacts. It authorizes only those agent
ingestion endpoints, not operator or read APIs. The deployment has exactly one
organization; ingestion fails clearly if that invariant is absent. Provision
that organization explicitly before agents start; ingestion never creates or
selects an organization.

## Licensing

SECentral application/source code is licensed under [MIT](LICENSE).
Distributed SELinux catalog artifacts under `catalogs/` are **GPL-2.0-or-later
unless otherwise noted**; this does not relicense the MIT application. See the
[catalog contract and attribution](catalogs/README.md) and shared
[license text](catalogs/LICENSES/GPL-2.0-or-later.txt).
