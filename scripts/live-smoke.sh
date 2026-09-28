#!/usr/bin/env bash
# Opt-in LIVE smoke test on the cluster (uses a real subscription login; small prompt).
#   scripts/live-smoke.sh codex     # requires: acp-runnerctl auth enroll codex personal-1
#   scripts/live-smoke.sh claude    # requires: acp-runnerctl auth enroll claude max-1
# Success = run Succeeded, patch parses, only add.sh changed, patch applies to the base
# revision and `sh test.sh` prints PASS. No assertion on natural-language output.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
D=${1:?codex|claude}; NS=acp-agents; RUN=$D-smoke-1
kubectl apply -f "$ROOT/deploy/examples/runnerclass-$D.yaml"
kubectl -n $NS delete acprun $RUN --ignore-not-found --wait=true
kubectl apply -f "$ROOT/deploy/examples/acprun-$D-smoke.yaml"
for _ in $(seq 1 900); do
  P=$(kubectl -n $NS get acprun $RUN -o jsonpath='{.status.phase}' 2>/dev/null || true)
  case "$P" in Succeeded|Failed|Cancelled) break ;; esac; sleep 1
done
kubectl -n $NS get acprun $RUN -o yaml | sed -n '/^status:/,$p'
[ "$P" = Succeeded ] || { echo "live smoke FAILED ($P)"; exit 1; }
eval "$("$ROOT/scripts/port-forward-db.sh")"
cargo run -q --manifest-path "$ROOT/Cargo.toml" -p acp-runnerctl -- run artifact $RUN -n $NS -o /tmp/$RUN.patch
TMP=$(mktemp -d); "$ROOT/scripts/build-fixture-repo.sh" "$TMP/fixture.git" >/dev/null
git clone -q "$TMP/fixture.git" "$TMP/wt"
CHANGED=$(git -C "$TMP/wt" apply --numstat /tmp/$RUN.patch | awk '{print $3}')
[ "$CHANGED" = "add.sh" ] || { echo "unexpected changed paths: $CHANGED"; exit 1; }
git -C "$TMP/wt" apply --check /tmp/$RUN.patch && git -C "$TMP/wt" apply /tmp/$RUN.patch
(cd "$TMP/wt" && sh test.sh)
echo "live smoke ($D): PASSED"
