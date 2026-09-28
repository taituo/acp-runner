#!/usr/bin/env bash
# Resolve base image tags to digests and pin them in the Dockerfiles' ARG defaults.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
for f in "$ROOT/images/runner/Dockerfile" "$ROOT/images/controller/Dockerfile"; do
  grep -E '^ARG [A-Z_]+_IMAGE=' "$f" | while IFS== read -r lhs ref; do
    base=${ref%@*}
    digest=$(docker buildx imagetools inspect "$base" --format '{{json .Manifest}}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["digest"])')
    sed -i "s|^$lhs=.*|$lhs=$base@$digest|" "$f"
    echo "$lhs=$base@$digest"
  done
done
