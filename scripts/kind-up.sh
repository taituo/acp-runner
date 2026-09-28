#!/usr/bin/env bash
# Create the KIND cluster (kind >= v0.33.0 so kindnetd enforces NetworkPolicy).
#   go install sigs.k8s.io/kind@v0.33.0   (or download a release binary)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
command -v kind >/dev/null || { echo "kind not found (go install sigs.k8s.io/kind@v0.33.0)"; exit 1; }
kind get clusters | grep -qx acp-runner || kind create cluster --config "$ROOT/deploy/kind/kind-config.yaml"
kubectl cluster-info --context kind-acp-runner
