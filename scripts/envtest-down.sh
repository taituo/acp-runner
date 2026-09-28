#!/usr/bin/env bash
# Stop the control plane started by scripts/envtest-up.sh.
set -euo pipefail
DIR=${ENVTEST_DIR:-${TMPDIR:-/tmp}/acp-runner-envtest}
for p in apiserver etcd; do
  f="$DIR/$p.pid"
  [ -f "$f" ] || continue
  pid=$(cat "$f")
  kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 40); do kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
  kill -9 "$pid" 2>/dev/null || true
  rm -f "$f"
done
rm -rf "$DIR/etcd"
