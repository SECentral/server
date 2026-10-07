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
is needed). The same command is included in `bin/ci`:

```sh
podman run --rm --userns=keep-id -v "$PWD:/workspace/server:z" \
  -w /workspace/server secentral-server-dev bundle exec archspec check
```

`Archspec.rb` keeps models, services, queries, and jobs independent of controllers
and HTTP APIs, and bans obvious persistence calls in queries. It analyzes application
Ruby and library/task files, not specs or frontend code. Inspect reported evidence
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

Then prepare the test database and run the suite from `server/`:

```sh
podman run --rm --network secentral-test --userns=keep-id \
  -v "$PWD:/workspace/server:z" -w /workspace/server \
  -e RAILS_ENV=test \
  -e DATABASE_URL=postgresql://secentral:secentral@db:5432/secentral_server_test \
  secentral-server-dev bash -lc 'bundle exec rails db:prepare && bundle exec rspec'
```

Remove the temporary database and network when finished:

```sh
podman rm -f secentral-test-db
podman network rm secentral-test
```
