#!/usr/bin/env bash
# Expose the in-cluster dev PostgreSQL on 127.0.0.1:15432 for acp-runnerctl.
#   eval "$(scripts/port-forward-db.sh)"
set -euo pipefail
kubectl -n acp-runner-system port-forward svc/acp-runner-postgres 15432:5432 >/dev/null 2>&1 &
sleep 2
PW=$(kubectl -n acp-runner-system get secret acp-runner-db -o jsonpath='{.data.password}' | base64 -d)
echo "export DATABASE_URL=postgres://acp:${PW}@127.0.0.1:15432/acp_runner"
