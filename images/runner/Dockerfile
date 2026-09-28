# syntax=docker/dockerfile:1.7
#
# acp-runner runner image: runnerd (trusted supervisor) + agentd (untrusted executor) + git +
# CA certificates + generic runtime deps. The same image runs both containers of an attempt
# pod; the pod spec decides which binary runs where and what each one can see.
#
# Harnesses: with a HarnessProvider configured (v3), environments get their harness as a
# pinned, digest-verified artifact materialized into /opt/harness during the trusted
# bootstrap — one runtime image for every harness. The CLIs installed below are the
# built-in fallback (and what one-shot ACPRuns use); build with `--build-arg WITH_CLIS=0`
# for a harness-less runtime image.
#
# Pinning:
#   * CLI/adapter versions: images/runner/package.json + package-lock.json (npm ci, integrity-checked)
#   * compatibility status: drivers.lock.yaml (checked against package.json by tests)
#   * base images: pin by digest for production (scripts/pin-base-images.sh rewrites the ARGs)
# The CLIs never self-update at runtime (DISABLE_AUTOUPDATER / check_for_update_on_startup=false,
# read-only root filesystem).
#
# Build from the repository root:
#   docker build -f images/runner/Dockerfile -t acp-runner/runner:dev .

ARG RUST_IMAGE=docker.io/library/rust:1.95-bookworm
ARG NODE_IMAGE=docker.io/library/node:22-bookworm-slim
ARG WITH_CLIS=1

FROM ${RUST_IMAGE} AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates crates
COPY bins bins
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked -p runnerd -p agentd -p fake-acp-agent \
 && install -D -m 0755 target/release/runnerd /out/runnerd \
 && install -D -m 0755 target/release/agentd /out/agentd \
 && install -D -m 0755 target/release/fake-acp-agent /out/fake-acp-agent

FROM ${NODE_IMAGE} AS clis
ARG WITH_CLIS
WORKDIR /opt/acp-runner
COPY images/runner/package.json images/runner/package-lock.json ./
RUN if [ "$WITH_CLIS" = "1" ]; then npm ci --omit=dev --no-audit --no-fund && npm cache clean --force; \
    else mkdir -p node_modules/.bin; fi

FROM ${NODE_IMAGE} AS fixtures
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
COPY tests/fixtures/buggy-repo /src/tests/fixtures/buggy-repo
COPY scripts/build-fixture-repo.sh /src/scripts/build-fixture-repo.sh
RUN /src/scripts/build-fixture-repo.sh /out/buggy-repo.git > /out/buggy-repo.sha

FROM ${NODE_IMAGE}
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates tini bash ripgrep procps python3 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 10001 agent && useradd -u 10001 -g 10001 -d /home/agent -M -s /bin/bash agent \
 && mkdir -p /workspace /home/agent /run/acp-runner /var/lib/acp-runner /opt/acp-runner/fixtures /opt/harness \
 && chown 10001:10001 /workspace /home/agent /run/acp-runner /var/lib/acp-runner /opt/harness
COPY --from=clis /opt/acp-runner/node_modules /opt/acp-runner/node_modules
COPY --from=build /out/runnerd /usr/local/bin/runnerd
COPY --from=build /out/agentd /usr/local/bin/agentd
COPY --from=build /out/fake-acp-agent /usr/local/bin/fake-acp-agent
COPY --from=fixtures --chown=10001:10001 /out/ /opt/acp-runner/fixtures/
COPY drivers.lock.yaml /opt/acp-runner/drivers.lock.yaml
ENV PATH=/opt/acp-runner/node_modules/.bin:/usr/local/bin:/usr/bin:/bin \
    HOME=/home/agent \
    DISABLE_AUTOUPDATER=1 \
    DISABLE_UPDATES=1 \
    npm_config_update_notifier=false
USER 10001:10001
WORKDIR /workspace
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/runnerd"]
CMD ["pod"]
