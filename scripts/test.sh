#!/usr/bin/env bash
# All deterministic tests (no provider accounts needed).
#
#   scripts/test.sh              unit + integration tests; PostgreSQL-backed tests run when
#                                ACP_TEST_DATABASE_URL is set, Kubernetes e2e when
#                                ACP_E2E_KUBECONFIG is set (scripts/envtest-up.sh)
set -euo pipefail
cd "$(dirname "$0")/.."
# V8.3: fixtures use file:// repository URLs (default-deny otherwise).
export ACP_RUNNER_ALLOW_FILE_REPOS=true
cargo fmt --all -- --check || echo "warning: rustfmt differences"
cargo clippy --workspace --all-targets -q -- -D warnings
cargo build -q -p fake-acp-agent -p runnerd -p agentd -p acp-runner-controller -p acp-egress-proxy -p acp-openai-shim
cargo test --workspace -q
if [ -z "${ACP_TEST_DATABASE_URL:-}" ]; then
  echo "NOTE: ACP_TEST_DATABASE_URL unset — journal/engine/kube e2e tests were skipped (scripts/dev-postgres.sh)"
fi
if [ -z "${ACP_E2E_KUBECONFIG:-}" ]; then
  echo "NOTE: ACP_E2E_KUBECONFIG unset — Kubernetes e2e test was skipped (scripts/envtest-up.sh)"
fi
