#!/usr/bin/env bash
# Start a development PostgreSQL and print the URLs to export.
#   docker compose (default) or, without Docker, a local cluster via initdb/pg_ctl (--local).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
if [ "${1:-}" = "--local" ] || ! command -v docker >/dev/null 2>&1; then
  PGBIN=${PGBIN:-$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)}
  DATA=${PGDATA_DIR:-$ROOT/.acp-runner-dev/pgdata}
  if [ ! -d "$DATA" ]; then "$PGBIN/initdb" -D "$DATA" -U acp --auth=trust >/dev/null; fi
  "$PGBIN/pg_ctl" -D "$DATA" -o "-p 55432 -k /tmp" -l "$DATA/../postgres.log" status >/dev/null 2>&1 \
    || "$PGBIN/pg_ctl" -D "$DATA" -o "-p 55432 -k /tmp" -l "$DATA/../postgres.log" start >/dev/null
  sleep 1
  psql -h 127.0.0.1 -p 55432 -U acp -d postgres -tc "SELECT 1 FROM pg_database WHERE datname='acp_runner'" | grep -q 1 \
    || psql -h 127.0.0.1 -p 55432 -U acp -d postgres -qc "CREATE DATABASE acp_runner"
  echo "export DATABASE_URL=postgres://acp@127.0.0.1:55432/acp_runner"
  echo "export ACP_TEST_DATABASE_URL=postgres://acp@127.0.0.1:55432/postgres"
  exit 0
fi
docker compose -f "$ROOT/docker-compose.yaml" up -d --wait postgres >/dev/null
echo "export DATABASE_URL=postgres://acp:acp@127.0.0.1:55432/acp_runner"
echo "export ACP_TEST_DATABASE_URL=postgres://acp:acp@127.0.0.1:55432/postgres"
