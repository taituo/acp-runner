#!/usr/bin/env bash
# Propose a CLI/adapter upgrade and run the regression suite against it.
#
#   scripts/upgrade-cli.sh codex 0.157.1           # @openai/codex
#   scripts/upgrade-cli.sh codex-acp 1.14.0        # @agentclientprotocol/codex-acp
#   scripts/upgrade-cli.sh claude 2.1.283          # @anthropic-ai/claude-code
#
# Steps: pin exact version in images/runner/package.json -> regenerate package-lock.json ->
# mark the drivers.lock.yaml entry `candidate` -> host compatibility suite (fake + unauthenticated
# real CLI; live targets too when their credential env vars are set) -> optional candidate image
# (--image) + in-image suite -> record the resulting status.
# Nothing outside images/runner/ and drivers.lock.yaml changes unless the driver contract changed.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WHAT=${1:?component: codex | codex-acp | claude}; VERSION=${2:?version}; IMAGE_BUILD=${3:-}
case "$WHAT" in
  codex) PKG="@openai/codex"; DRIVER=codex; FIELD=cli ;;
  codex-acp) PKG="@agentclientprotocol/codex-acp"; DRIVER=codex; FIELD=adapter ;;
  claude) PKG="@anthropic-ai/claude-code"; DRIVER=claude; FIELD=cli ;;
  *) echo "unknown component $WHAT"; exit 2 ;;
esac
set_lock() { # driver field version status
  python3 - "$ROOT/drivers.lock.yaml" "$@" <<'PY'
import re, sys, datetime
path, driver, field, version, status = sys.argv[1:6]
s = open(path).read()
m = re.search(r"\n  - driver: %s\n(?:    .*\n|      .*\n)*" % re.escape(driver), s)
block = m.group(0)
nb = block
if field != "-":
    nb = re.sub(r"(\n    %s: \{package: \"[^\"]+\", version: )[^}]+(\})" % field, r"\g<1>%s\g<2>" % version, nb)
nb = re.sub(r"(\n    status: ).*", r"\g<1>%s" % status, nb)
nb = re.sub(r'(\n      date: )"[^"]*"', r'\g<1>"%s"' % datetime.date.today().isoformat(), nb)
open(path, "w").write(s.replace(block, nb))
PY
}
cd "$ROOT/images/runner"
python3 - "$PKG" "$VERSION" <<'PY'
import json, sys
pkg, ver = sys.argv[1:3]
p = json.load(open("package.json"))
p["dependencies"][pkg] = ver
open("package.json", "w").write(json.dumps(p, indent=2) + "\n")
PY
npm install --package-lock-only --no-audit --no-fund >/dev/null
set_lock "$DRIVER" "$FIELD" "$VERSION" candidate
echo "pinned $PKG@$VERSION (candidate)"
cd "$ROOT"
TARGETS="fake-acp,fake-claude"
[ "$DRIVER" = codex ] && TARGETS="$TARGETS,codex-noauth"
LIVE=0
if [ "$DRIVER" = codex ] && [ -n "${ACP_COMPAT_CODEX_AUTH_JSON:-}" ]; then TARGETS="$TARGETS,codex"; LIVE=1; fi
if [ "$DRIVER" = claude ] && [ -n "${ACP_COMPAT_CLAUDE_TOKEN_FILE:-}" ]; then TARGETS="$TARGETS,claude"; LIVE=1; fi
if "$ROOT/scripts/compat.sh" --targets "$TARGETS"; then
  if [ "$LIVE" = 1 ]; then STATUS=compatible
  elif [ "$DRIVER" = codex ]; then STATUS=compatible-unauthenticated
  else STATUS=contract-verified-with-fake; fi
else
  STATUS=incompatible
fi
if [ "$IMAGE_BUILD" = "--image" ] && [ "$STATUS" != incompatible ]; then
  TAG="candidate-$WHAT-$VERSION"
  "$ROOT/scripts/build-images.sh" --tag "$TAG"
  IT="fake-acp"; [ "$DRIVER" = codex ] && IT="$IT,codex-noauth"
  [ "$LIVE" = 1 ] && IT="$IT,$DRIVER"
  "$ROOT/scripts/compat-image.sh" "acp-runner/runner:$TAG" "$IT" || STATUS=incompatible
fi
set_lock "$DRIVER" "-" "-" "$STATUS"
echo "drivers.lock.yaml: $DRIVER -> $STATUS"
[ "$STATUS" != incompatible ]
