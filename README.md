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

## Self-hosted deployment

The production `Containerfile` builds the Rails application and its SPA. The
`Containerfile.dev` is only for development and tests. To deploy with PostgreSQL
and automatic HTTPS:

1. Point a public DNS name at the host and allow inbound TCP ports 80 and 443
   (and UDP 443 for HTTP/3).
2. Copy `.env.example` to `.env`, then set `DOMAIN`, `SECRET_KEY_BASE`,
   `SECENTRAL_SERVER_DATABASE_PASSWORD`, and `SECENTRAL_INGESTION_KEY` to
   unique generated values. For random values, use `openssl rand -hex 32`.
3. Set `ADMIN_USERNAME` and `ADMIN_PASSWORD_DIGEST`. Generate a bcrypt digest
   for your chosen operator password with the development image:

   ```sh
   docker build -f Containerfile.dev -t secentral-server-dev .
   read -rsp 'Operator password: ' ADMIN_PASSWORD; printf '\n'
   printf '%s' "$ADMIN_PASSWORD" | docker run --rm -i secentral-server-dev \
     bundle exec ruby -rbcrypt -e 'puts BCrypt::Password.create(STDIN.read)'
   unset ADMIN_PASSWORD
   ```

   Put the printed digest in `.env` as `ADMIN_PASSWORD_DIGEST`.
4. Start the services with `docker compose up -d --build`.
5. Open `https://<DOMAIN>` and sign in with the configured operator account.

Keep `.env` private and back up the PostgreSQL volume. The Compose deployment
uses Caddy to obtain and renew HTTPS certificates. It publishes the Rails app
through Caddy only; PostgreSQL is not published to the host. `docker compose
down` preserves the database volume; `docker compose down -v` deletes it.

Agent hosts must use the same `SECENTRAL_INGESTION_KEY` value for bearer
authentication.

To upgrade after updating the server source, run `docker compose up -d --build`;
the application entrypoint prepares the database and applies migrations. Back
up the database before upgrades, for example:

```sh
docker compose exec -T db pg_dump -U secentral_server secentral_server_production > secentral-backup.sql
```

## Current capabilities

Agents can submit authenticated events, heartbeats, expected-context
observations, and requested policy artifacts. The server persists raw event
evidence, normalizes and groups occurrences into issues, and exposes operator
views for issues, hosts, SELinux activity, configuration, catalogs, analysis,
and resolution intent. Policy drafts can be staged and exported for review.

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
