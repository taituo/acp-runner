# syntax=docker/dockerfile:1.7
# acp-runner controller (+ acp-runnerctl). Build from the repository root:
#   docker build -f images/controller/Dockerfile -t acp-runner/controller:dev .
# Ships the controller, acp-runnerctl and the acp-egress-proxy (deployed separately in the
# acp-egress namespace; see deploy/egress-proxy/).
ARG RUST_IMAGE=docker.io/library/rust:1.95-bookworm
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian12:nonroot

FROM ${RUST_IMAGE} AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates crates
COPY bins bins
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked -p acp-runner-controller -p acp-runnerctl -p acp-egress-proxy \
 && install -D -m 0755 target/release/acp-runner-controller /out/acp-runner-controller \
 && install -D -m 0755 target/release/acp-runnerctl /out/acp-runnerctl \
 && install -D -m 0755 target/release/acp-egress-proxy /out/acp-egress-proxy

FROM ${RUNTIME_IMAGE}
COPY --from=build /out/ /usr/local/bin/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/acp-runner-controller"]
CMD ["run"]
