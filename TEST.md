# Development and tests

Ruby, Bundler, Rails, Rake, and RSpec must run inside Podman containers. The
development image also provides Node.js 24 LTS, npm, and PostgreSQL client tools. Run
these commands from the repository root (the directory containing
`Containerfile.dev`). The production `Containerfile` is not a development image.

Build the image (repeat after changing `Gemfile`, `Gemfile.lock`, or
`Containerfile.dev`):

```sh
podman build -f Containerfile.dev -t secentral-server-dev .
```

Install frontend dependencies and run its checks:

In the volume options, `$PWD` is your checkout and `/workspace/server` is its
mount path inside the container.

```sh
podman run --rm --userns=keep-id -v "$PWD:/workspace/server:z" \
  -w /workspace/server/frontend secentral-server-dev npm ci
podman run --rm --userns=keep-id -v "$PWD:/workspace/server:z" \
  -w /workspace/server/frontend secentral-server-dev npm test
podman run --rm --userns=keep-id -v "$PWD:/workspace/server:z" \
  -w /workspace/server/frontend secentral-server-dev npm run lint
podman run --rm --userns=keep-id -v "$PWD:/workspace/server:z" \
  -w /workspace/server/frontend secentral-server-dev npm run build
```

`npm run build` generates API types from `openapi/openapi.yaml`, type-checks,
builds the SPA, and checks the generated output.

Run RuboCop before RSpec to catch style violations locally:

```sh
podman run --rm --userns=keep-id -v "$PWD:/workspace/server:z" \
  -w /workspace/server secentral-server-dev bin/rubocop
```

Run architecture checks before database-backed specs (no Rails boot or database
is needed). The same command is included in `bin/ci` and GitHub Actions:

```sh
podman run --rm --userns=keep-id -v "$PWD:/workspace/server:z" \
  -w /workspace/server secentral-server-dev bundle exec archspec check
```

`Archspec.rb` keeps models, services, queries, jobs, and shared library Ruby code
independent of controllers, middleware, and HTTP APIs, and bans obvious
persistence calls in queries. It analyzes application Ruby and library/task
files, not specs or frontend code. Inspect reported evidence
before changing the rules; unknown/dynamic receivers and indirect writes are not
proof of correctness. The initial rules need no baseline or suppressions.

The architecture regression spec tests the actual CLI against temporary positive
and forbidden examples without changing application files or booting Rails:

```sh
podman run --rm --userns=keep-id -v "$PWD:/workspace/server:z" \
  -w /workspace/server secentral-server-dev bundle exec rspec spec/architecture_spec.rb
```

Run RSpec against an isolated PostgreSQL container. Start the database on a
Podman network:

```sh
podman network create secentral-test
podman run -d --name secentral-test-db --network secentral-test \
  --network-alias db -e POSTGRES_USER=secentral \
  -e POSTGRES_PASSWORD=secentral -e POSTGRES_DB=secentral_server_test \
  docker.io/library/postgres:16
until podman exec secentral-test-db pg_isready -U secentral -d secentral_server_test; do
  sleep 1
done
```

Then load the schema and run the suite from `server/`. This replaces the schema
and data, so use only the isolated test database above. Unlike `db:prepare`,
`db:schema:load` does not insert the default organization from the seeds:

```sh
podman run --rm --network secentral-test --userns=keep-id \
  -v "$PWD:/workspace/server:z" -w /workspace/server \
  -e RAILS_ENV=test \
  -e DATABASE_URL=postgresql://secentral:secentral@db:5432/secentral_server_test \
  secentral-server-dev bash -c 'bundle exec rails db:schema:load && bundle exec rspec'
```

### RSpec isolation

Transactional fixtures are disabled globally. For ordinary database examples
that use one connection, prefer a local rollback transaction around each
example, as in `spec/requests/overview_spec.rb`. Existing groups with explicit
cleanup can be converted individually after checking their behavior; do not
enable transactions globally.

Keep committed data and explicit cleanup for tests that require independent
connections or real transaction boundaries:

- `spec/requests/events_spec.rb`, `reporting_duration_spec.rb`, and
  `catalog_imports_spec.rb`; `spec/models/catalog_management_spec.rb`;
  `spec/services/import_distribution_catalog_spec.rb`,
  `distribution_catalog_reference_spec.rb`, and
  `policy_permissive_domains_spec.rb` contain cross-thread database cases.
- `spec/requests/mcp_spec.rb` exercises standalone read-only transactions,
  pooled connection cleanup, and concurrent commits. It cleans all application
  tables and must never share its database with another test process.
- `spec/services/catalog_update_workflow_spec.rb` checks a fresh Rails process
  against committed data. Migration specs create and remove separate schemas.

Rollback does not restore environment variables, controller configuration,
notification subscriptions, queued jobs, threads, or subprocesses. Restore or
clean those separately, including when an example fails. Recheck these
requirements when adding or converting a group; this list identifies current
exceptions, not a guarantee about future specs.

Remove the temporary database and network when finished:

```sh
podman rm -f secentral-test-db
podman network rm secentral-test
```
