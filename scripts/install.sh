#!/usr/bin/env bash
# Install CRDs, controller, dev PostgreSQL, agent namespace + policies and fake runner
# classes into the current kubectl context (KIND by default).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
kubectl apply -f "$ROOT/deploy/crds/acp-runner.dev_crds.yaml"
kubectl apply -f "$ROOT/deploy/controller/namespace.yaml" -f "$ROOT/deploy/agents/namespace.yaml"
kubectl apply -f "$ROOT/deploy/controller/rbac.yaml"
kubectl apply -f "$ROOT/deploy/postgres/postgres-dev.yaml"
kubectl -n acp-runner-system rollout status statefulset/acp-runner-postgres --timeout=180s
kubectl apply -f "$ROOT/deploy/controller/controller.yaml" -f "$ROOT/deploy/controller/networkpolicy.yaml"
kubectl apply -f "$ROOT/deploy/agents/networkpolicy.yaml"
kubectl -n acp-runner-system rollout status deployment/acp-runner-controller --timeout=180s
kubectl apply -f "$ROOT/deploy/examples/runnerclasses-fake.yaml"
echo "installed; try: kubectl apply -f deploy/examples/acprun-fake.yaml && kubectl -n acp-agents get acpruns -w"
