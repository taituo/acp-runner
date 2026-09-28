#!/usr/bin/env bash
# Run a driver contract smoke inside a runner image with `runnerd local`.
#   scripts/compat-image.sh IMAGE TARGETS
# Targets: fake-acp | codex-noauth | codex (needs ACP_COMPAT_CODEX_AUTH_JSON) | claude (needs ACP_COMPAT_CLAUDE_TOKEN_FILE)
set -euo pipefail
IMAGE=$1; TARGETS=$2
SHA=dab04cf7a90ba80a2e188cd4864c71abf7b39a74
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
chmod 0777 "$WORK"
run_target() {
  local t=$1 driver config expect creds="" prompt="Fix add.sh so that sh test.sh prints PASS. Only modify add.sh."
  case "$t" in
    fake-acp) driver=fake; config='{"command":"/usr/local/bin/fake-acp-agent","scenario":"fix"}'; expect=Succeeded ;;
    codex-noauth) driver=codex; config='{}'; expect=Failed ;;
    codex) driver=codex; config='{}'; expect=Succeeded
      creds='{"provider":"codex","profile":"compat","files":[{"key":"auth.json","target":".codex/auth.json","mode":384,"writeback":true}],"env":[]}'
      mkdir -p "$WORK/secret-$t"; cp "${ACP_COMPAT_CODEX_AUTH_JSON:?}" "$WORK/secret-$t/cred.auth.json" ;;
    claude) driver=claude; config='{}'; expect=Succeeded
      creds='{"provider":"claude","profile":"compat","files":[],"env":[{"key":"oauth-token","envName":"CLAUDE_CODE_OAUTH_TOKEN"}]}'
      mkdir -p "$WORK/secret-$t"; cp "${ACP_COMPAT_CLAUDE_TOKEN_FILE:?}" "$WORK/secret-$t/cred.oauth-token" ;;
    *) echo "unknown target $t"; return 2 ;;
  esac
  mkdir -p "$WORK/$t" "$WORK/secret-$t"; chmod -R a+rwX "$WORK"
  cat > "$WORK/$t/spec.json" <<JSON
{"wireVersion":2,"runId":"00000000-0000-0000-0000-000000000001","attemptId":"00000000-0000-0000-0000-000000000002",
 "taskId":"compat","ordinal":1,"classAttempt":1,"runnerClass":"compat-$t",
 "driver":{"name":"$driver","config":$config},
 "repository":{"url":"file:///opt/acp-runner/fixtures/buggy-repo.git","revision":"$SHA"},
 "prompt":"$prompt",
 "output":{"kind":"Patch","requireChanges":true,"maxPatchBytes":1048576},
 "timeouts":{"hardSeconds":900,"noProgressSeconds":300,"graceSeconds":10,"heartbeatSeconds":10,"startupSeconds":180},
 "permissions":{"mode":"AllowAll"},"credentials":${creds:-null},"recordRawPayloads":true}
JSON
  docker run --rm --read-only --tmpfs /tmp --tmpfs /workspace:uid=10001 --tmpfs /home/agent:uid=10001 \
    --cap-drop ALL --security-opt no-new-privileges \
    -v "$WORK/$t:/out" -v "$WORK/secret-$t:/secret:ro" "$IMAGE" \
    local --spec /out/spec.json --out /out --workspace /workspace --home /home/agent --tmp /tmp --secret-dir /secret >/dev/null
  local phase; phase=$(python3 -c "import json;print(json.load(open('$WORK/$t/result.json'))['phase'])")
  echo "$t: $phase (expected $expect)"
  [ "$phase" = "$expect" ] || { cat "$WORK/$t/events.jsonl" | tail -20; return 1; }
  if [ "$expect" = Succeeded ]; then
    test -s "$WORK/$t/patch.diff" && grep -q '^diff --git a/add.sh' "$WORK/$t/patch.diff"
  fi
}
IFS=, ; for t in $TARGETS; do run_target "$t"; done
echo "compat-image: PASSED for $TARGETS on $IMAGE"
