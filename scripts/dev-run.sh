#!/usr/bin/env bash
# Run an ACPRun manifest locally (no Kubernetes): engine + ingest + runnerd processes +
# agentd + fake agent, journaled in PostgreSQL. Requires DATABASE_URL (see scripts/dev-postgres.sh).
#
#   scripts/dev-run.sh deploy/examples/local/acprun-fallback.yaml
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
RUN=${1:-$ROOT/deploy/examples/local/acprun-fake.yaml}
: "${DATABASE_URL:?set DATABASE_URL (scripts/dev-postgres.sh prints one)}"
cargo build -q -p runnerd -p agentd -p fake-acp-agent -p acp-runner-controller -p acp-runnerctl --manifest-path "$ROOT/Cargo.toml"
"$ROOT/scripts/build-fixture-repo.sh" /tmp/acp-runner-fixtures/buggy-repo.git >/dev/null
# V8.3: local fixtures use file:// repository URLs (default-deny otherwise).
export ACP_RUNNER_ALLOW_FILE_REPOS=true
export PATH="$ROOT/target/debug:$PATH"
exec acp-runner-controller dev-run \
  --run "$RUN" \
  --classes "$ROOT/deploy/examples/local/runnerclasses-fake.yaml" \
  --work-dir "$ROOT/.acp-runner-dev"
