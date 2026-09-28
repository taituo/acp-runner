#!/usr/bin/env bash
# Build the runner and controller images.
#   scripts/build-images.sh                       # acp-runner/{runner,controller}:dev
#   scripts/build-images.sh --tag candidate-x     # candidate image for an upgrade
#   scripts/build-images.sh --kind                # also `kind load` into the acp-runner cluster
#   scripts/build-images.sh --push ghcr.io/me     # push and record the runner digest in drivers.lock.yaml
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TAG=dev; KIND=0; PUSH=""
while [ $# -gt 0 ]; do
  case "$1" in
    --tag) TAG=$2; shift 2 ;;
    --kind) KIND=1; shift ;;
    --push) PUSH=$2; shift 2 ;;
    *) echo "unknown arg $1"; exit 2 ;;
  esac
done
REPO=${PUSH:-acp-runner}
docker build -f "$ROOT/images/runner/Dockerfile" -t "$REPO/runner:$TAG" "$ROOT"
docker build -f "$ROOT/images/controller/Dockerfile" -t "$REPO/controller:$TAG" "$ROOT"
if [ "$KIND" = 1 ]; then
  kind load docker-image --name acp-runner "$REPO/runner:$TAG" "$REPO/controller:$TAG"
fi
if [ -n "$PUSH" ]; then
  docker push "$REPO/runner:$TAG"
  docker push "$REPO/controller:$TAG"
  DIGEST=$(docker inspect --format '{{index .RepoDigests 0}}' "$REPO/runner:$TAG" | sed 's/.*@//')
  python3 - "$ROOT/drivers.lock.yaml" "$REPO/runner" "$TAG" "$DIGEST" <<'PY'
import re, sys
path, repo, tag, digest = sys.argv[1:5]
s = open(path).read()
s = re.sub(r"(\n  repository: ).*", r"\g<1>" + repo, s, count=1)
s = re.sub(r"(\n  tag: ).*", r"\g<1>" + tag, s, count=1)
s = re.sub(r"(\n  digest: ).*", r"\g<1>" + digest, s, count=1)
open(path, "w").write(s)
PY
  echo "recorded $REPO/runner:$TAG@$DIGEST in drivers.lock.yaml"
fi
# Smoke: the pinned CLIs are present and report the locked versions.
docker run --rm --entrypoint sh "$REPO/runner:$TAG" -c 'codex --version; codex-acp --version; claude --version; runnerd --version; agentd --version; git --version'
