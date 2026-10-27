# syntax=docker/dockerfile:1
# check=error=true

# This Containerfile is designed for production, not development. Use with Kamal or build'n'run by hand:
# docker build -t secentral_server .
# docker run -d -p 80:80 -e RAILS_MASTER_KEY=<value from config/master.key> --name secentral_server secentral_server

# For a containerized dev environment, see Dev Containers: https://guides.rubyonrails.org/getting_started_with_devcontainer.html

# Make sure RUBY_VERSION matches the Ruby version in .ruby-version
ARG RUBY_VERSION=4.0.9
FROM docker.io/library/node:24-trixie-slim AS node
FROM docker.io/library/ruby:$RUBY_VERSION-slim-trixie AS policy-tools
COPY script/build_policy_tools.sh /tmp/build_policy_tools.sh
RUN sh /tmp/build_policy_tools.sh

FROM docker.io/library/ruby:$RUBY_VERSION-slim-trixie AS base

# Rails app lives here
WORKDIR /rails

# Install base packages
RUN apt-get update -qq && \
    apt-get upgrade --no-install-recommends -y && \
    apt-get install --no-install-recommends -y curl libjemalloc2 postgresql-client python3 python3-networkx libselinux1 && \
    ln -s /usr/lib/$(uname -m)-linux-gnu/libjemalloc.so.2 /usr/local/lib/libjemalloc.so && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=policy-tools /opt/secentral-policy-tools /opt/secentral-policy-tools
ENV PATH="/opt/secentral-policy-tools/bin:${PATH}"
RUN python3 -c 'import ctypes, setools; assert setools.__version__ == "4.6.0"; assert ctypes.CDLL("/opt/secentral-policy-tools/lib/libsepol.so.2").sepol_policy_kern_vers_max() >= 35'

# Set production environment variables and enable jemalloc for reduced memory usage and latency.
ENV RAILS_ENV="production" \
    BUNDLE_DEPLOYMENT="1" \
    BUNDLE_PATH="/usr/local/bundle" \
    BUNDLE_WITHOUT="development" \
    LD_PRELOAD="/usr/local/lib/libjemalloc.so"

# Throw-away build stage to reduce size of final image
FROM base AS build

# Install packages needed to build gems
RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y build-essential git libpq-dev libyaml-dev pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm && \
    ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

# Install application gems
COPY Gemfile Gemfile.lock ./

RUN bundle install && \
    rm -rf ~/.bundle/ "${BUNDLE_PATH}"/ruby/*/cache "${BUNDLE_PATH}"/ruby/*/bundler/gems/*/.git && \
    # -j 1 disable parallel compilation to avoid a QEMU bug: https://github.com/rails/bootsnap/issues/495
    bundle exec bootsnap precompile -j 1 --gemfile

# Copy application code
COPY . .

# Build the React SPA to public/spa (regenerates API types from openapi/).
RUN npm ci --prefix frontend && npm run build --prefix frontend
RUN rm -rf frontend/node_modules

# Precompile bootsnap code for faster boot times.
# -j 1 disable parallel compilation to avoid a QEMU bug: https://github.com/rails/bootsnap/issues/495
RUN bundle exec bootsnap precompile -j 1 app/ lib/




# Final stage for app image
FROM base

# Run and own only the runtime files as a non-root user for security
RUN groupadd --system --gid 1000 rails && \
    useradd rails --uid 1000 --gid 1000 --create-home --shell /bin/bash
USER 1000:1000

# Copy built artifacts: gems, application
COPY --chown=rails:rails --from=build "${BUNDLE_PATH}" "${BUNDLE_PATH}"
COPY --chown=rails:rails --from=build /rails /rails

# Entrypoint prepares the database.
ENTRYPOINT ["/rails/bin/docker-entrypoint"]

# Start server via Thruster by default, this can be overwritten at runtime
EXPOSE 80
CMD ["./bin/thrust", "./bin/rails", "server"]
