#!/usr/bin/env bash
# End-to-end on KIND with the fake driver (no provider accounts):
#   cluster -> images -> install -> fake run -> retry -> fallback -> hang/timeout ->
#   journal events + patch artifact -> sandbox security checks.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
NS=acp-agents
"$ROOT/scripts/kind-up.sh"
"$ROOT/scripts/build-images.sh" --kind
"$ROOT/scripts/install.sh"
cargo build -q --manifest-path "$ROOT/Cargo.toml" -p acp-runnerctl
CTL="$ROOT/target/debug/acp-runnerctl"

wait_phase() { # name, timeout seconds
  local name=$1 t=${2:-300} phase=""
  for _ in $(seq 1 "$t"); do
    phase=$(kubectl -n $NS get acprun "$name" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    case "$phase" in Succeeded|Failed|Cancelled) echo "$name: $phase"; return 0 ;; esac
    sleep 1
  done
  echo "$name did not finish (phase=$phase)"; kubectl -n $NS get acprun "$name" -o yaml; return 1
}

for f in acprun-fake acprun-retry acprun-fallback acprun-hang; do
  kubectl apply -f "$ROOT/deploy/examples/$f.yaml"
done
wait_phase fake-fix-1
wait_phase fake-retry-1
wait_phase fake-fallback-1
wait_phase fake-hang-1 400
kubectl -n $NS get acpruns

# journal + artifact through acp-runnerctl
eval "$("$ROOT/scripts/port-forward-db.sh")"
"$CTL" run get fake-fallback-1 -n $NS
"$CTL" run events fake-hang-1 -n $NS | grep -E "AttemptStarted|AttemptTimedOut|AttemptFailed|RunCompleted"
"$CTL" run artifact fake-fix-1 -n $NS -o /tmp/acp-fake-fix-1.patch
git -C "$(mktemp -d)" init -q && echo "patch written to /tmp/acp-fake-fix-1.patch"

# security checks on a live agent pod
kubectl -n $NS apply -f - <<YAML
apiVersion: acp-runner.dev/v1alpha1
kind: ACPRun
metadata: {name: security-probe}
spec:
  taskId: security-probe
  runnerClassName: fake-hang
  repository: {url: "file:///opt/acp-runner/fixtures/buggy-repo.git", revision: dab04cf7a90ba80a2e188cd4864c71abf7b39a74}
  prompt: {text: probe}
  timeouts: {noProgressSeconds: 120}
YAML
for _ in $(seq 1 120); do
  POD=$(kubectl -n $NS get acprun security-probe -o jsonpath='{.status.sandboxRef.name}' 2>/dev/null || true)
  [ -n "$POD" ] && kubectl -n $NS wait --for=condition=Ready "pod/$POD" --timeout=5s >/dev/null 2>&1 && break
  sleep 1
done
echo "--- security checks on $POD"
kubectl -n $NS exec "$POD" -- sh -c 'test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token && echo "OK: no service-account token"'
kubectl -n $NS exec "$POD" -- sh -c 'id -u | grep -qv "^0$" && echo "OK: non-root uid $(id -u)"'
kubectl -n $NS exec "$POD" -- sh -c 'touch /usr/x 2>/dev/null && echo "FAIL: rootfs writable" || echo "OK: read-only root filesystem"'
kubectl -n $NS exec "$POD" -- sh -c 'grep -q "^CapEff:\s*0000000000000000" /proc/self/status && echo "OK: no capabilities"'
kubectl -n $NS exec "$POD" -- sh -c 'grep -q "^NoNewPrivs:\s*1" /proc/self/status && echo "OK: no_new_privs"'
kubectl -n $NS exec "$POD" -- sh -c 'ls -l /var/run/acp-runner/attempt; mount | grep -E " /workspace | /tmp | /home/agent " '
kubectl -n $NS exec "$POD" -- sh -c 'timeout 5 bash -c "exec 3<>/dev/tcp/kubernetes.default.svc/443" 2>/dev/null && echo "FAIL: API server reachable" || echo "OK: Kubernetes API not reachable"'
kubectl -n $NS exec "$POD" -- sh -c 'timeout 5 bash -c "exec 3<>/dev/tcp/acp-runner-ingest.acp-runner-system.svc/8081" && echo "OK: ingest reachable"'
kubectl auth can-i get secrets -n acp-runner-system --as=system:serviceaccount:$NS:acp-runner-agent | grep -q no && echo "OK: agent SA cannot read Secrets"
kubectl -n $NS delete acprun security-probe --wait=true
echo "e2e-kind: done"
