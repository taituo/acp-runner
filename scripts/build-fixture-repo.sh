#!/usr/bin/env bash
# Build the fixture repository with a known bug as a *bare* git repo with a deterministic
# commit SHA (fixed author/committer/date), e.g. for the runner image:
#   scripts/build-fixture-repo.sh /opt/acp-runner/fixtures/buggy-repo.git
# The resulting SHA is printed; it is stable across machines and git versions using SHA-1.
set -euo pipefail
OUT=${1:?usage: build-fixture-repo.sh <output.git>}
SRC=$(cd "$(dirname "$0")/../tests/fixtures/buggy-repo" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cp -R "$SRC/." "$WORK/"
cd "$WORK"
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@example.invalid GIT_AUTHOR_DATE="2026-01-01T00:00:00Z"
export GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@example.invalid GIT_COMMITTER_DATE="2026-01-01T00:00:00Z"
git init -q --initial-branch=main
chmod 0755 add.sh test.sh
git add -A
git commit -q -m "buggy add"
rm -rf "$OUT"
git clone -q --bare . "$OUT"
git -C "$OUT" config uploadpack.allowAnySHA1InWant true
git rev-parse HEAD
