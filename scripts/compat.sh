#!/usr/bin/env bash
# Driver compatibility / regression suite.
#
#   scripts/compat.sh                                  # fake-acp, fake-claude, fake-codex, codex-noauth
#   scripts/compat.sh --targets fake-acp,fake-claude,fake-codex   # CI without npm access
#   ACP_COMPAT_CODEX_AUTH_JSON=~/.acp/codex-auth.json scripts/compat.sh --targets codex      # LIVE (opt-in)
#   ACP_COMPAT_CLAUDE_TOKEN_FILE=~/.acp/claude-token  scripts/compat.sh --targets claude     # LIVE (opt-in)
#   scripts/compat.sh --image acp-runner/runner:candidate-x --targets fake-acp,codex-noauth  # inside an image
#
# Host mode installs the CLIs pinned in images/runner/package-lock.json into .cache/clis
# (npm ci) so the suite runs against exactly the versions the image ships.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TARGETS="fake-acp,fake-claude,fake-codex,codex-noauth"
IMAGE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --targets) TARGETS=$2; shift 2 ;;
    --image) IMAGE=$2; shift 2 ;;
    *) echo "unknown arg $1"; exit 2 ;;
  esac
done

if [ -n "$IMAGE" ]; then
  # Image mode: run `runnerd local` inside the candidate image against the baked-in fixture.
  exec "$ROOT/scripts/compat-image.sh" "$IMAGE" "$TARGETS"
fi

if echo ",$TARGETS," | grep -Eq ',(codex|codex-noauth|claude),'; then
  CLIS="$ROOT/.cache/clis"
  if [ ! -f "$CLIS/.lock-sha" ] || [ "$(sha256sum "$ROOT/images/runner/package-lock.json" | cut -d' ' -f1)" != "$(cat "$CLIS/.lock-sha")" ]; then
    rm -rf "$CLIS" && mkdir -p "$CLIS"
    cp "$ROOT/images/runner/package.json" "$ROOT/images/runner/package-lock.json" "$CLIS/"
    (cd "$CLIS" && npm ci --omit=dev --no-audit --no-fund >/dev/null)
    sha256sum "$ROOT/images/runner/package-lock.json" | cut -d' ' -f1 > "$CLIS/.lock-sha"
  fi
  export ACP_COMPAT_PATH="$CLIS/node_modules/.bin:$(dirname "$(command -v node)"):/usr/local/bin:/usr/bin:/bin"
fi
export ACP_COMPAT_TARGETS="$TARGETS"
cd "$ROOT"
cargo build -q -p fake-acp-agent -p agentd
cargo test -p runnerd --test compat -- --test-threads=1
cargo test -p runnerd --test drivers_lock
echo "compat: PASSED for $TARGETS"
