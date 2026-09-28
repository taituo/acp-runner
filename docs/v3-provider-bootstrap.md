# v3 — Provider / Bootstrap layer

v3 adds the provider/bootstrap layer on top of the unchanged v2 runnerd/agentd base and the
AgentEnvironment primitive: bootstrap as plain data, a first-class workdir, one resolver model
for configs/agents/skills, workspace lineage with `branch()`, a raw ACP dataplane behind
restart-safe signed tickets, environment-lifetime credential leases, pinned harness artifacts in
one runtime image, and an OpenAI Responses shim as one more ACP client. No further
re-architecture is planned: new work is harness adapters, bundle/harness providers and edge
protocols.

```
                         PROVIDER API (control plane)
            create / get / connect / snapshot / branch / finish / cancel / destroy
                                     │
                                     ▼
                              AgentEnvironment
                                     │
          ┌──────────────────────────┴──────────────────────────┐
          │ control plane (heartbeat directives)                 │ data plane
          ▼                                                      ▼
       runnerd  (TRUSTED) ───────────── gateway: HTTP/1.1 + ticket → raw ACP (ndjson | WebSocket)
          │ IPC (agentd.sock: Launch/Proceed/Cancel/Finish)      │ acp-data.sock: bytes, verbatim
          ▼                                                      ▼
       agentd  (UNTRUSTED) ───────────────────────────────────► harness (ACP stdio agent)
          └── bootstrap.exec, tools, sub-agents, processes

   OpenAI Responses shim ── ACP client ──► the same gateway        (not in the core)
```

## 1. The spec

```yaml
externalRef: review-123
harness:
  name: claude
  version: 2.1.274            # with a HarnessProvider: a pinned artifact
  digest: sha256:…            # optional explicit pin
  config: {permissionMode: acceptEdits}
workspace:
  source: {type: git, url: https://…, revision: abc123}   # omitted → empty base (inference-only)
  overlays: [{type: patchArtifact, artifactId: S1}]        # inherited WORK (in the artifact)
  workdir: packages/backend                                # harness cwd, below /workspace
credentials: {profile: claude-max-1}                        # leased for the env's lifetime
agents: [backend-reviewer]                                  # bundle references
skills: [rust, postgres, company-review]
configs: [company-claude-project]                           # alias: configBundles
bootstrap:
  files:                                                    # runtime CONFIG (not in the artifact)
    - {bundle: reviewer-config, target: {root: workspace, path: CLAUDE.md}, artifactPolicy: exclude}
  exec:                                                     # execve(command, argv, env) in agentd
    - {command: /opt/harness/bin/setup, args: [--profile, coding], cwd: app}
lifetime: {idleSeconds: 600, maxSeconds: 3600}
output: {artifact: patch}                                   # or none (e.g. a review)
egress: {mode: proxy}
```

`crates/acp-runner-core/src/environment.rs` (`EnvironmentSpec`, validation, `EnvironmentOverrides`),
CRD `AgentEnvironment` (`crates/acp-runner-k8s/src/crds.rs`, examples
`deploy/examples/agentenvironment-{codex,review}.yaml`). Legacy v2 fields (`repository`,
`idleTimeoutSeconds`) still parse.

## 2. Bootstrap order and trust boundary

| # | step | where | trust |
|---|------|-------|-------|
| 1 | resolve harness: `HarnessProvider.resolve(name, version)`; pin check | provider | trusted |
|   | download, **digest verify**, safe extraction to `/opt/harness` | runnerd | trusted |
| 2 | checkout BASE at the exact revision (or the deterministic empty base) | runnerd | trusted |
| 3 | overlays: artifact metadata → **hash verify** → resolve the original repo/base → apply | provider + runnerd | trusted |
| 4 | configs/agents/skills + `bootstrap.files`: resolve → store (content-addressed) → fetch by digest → **verify** → place (`O_NOFOLLOW`) | provider + runnerd | trusted |
| 5 | credential lease (provider) + HOME skeleton (runnerd, no secrets) | provider + runnerd | trusted |
| 6 | validate workdir: real directory below `/workspace`, no `..`, no symlink on the way | runnerd | trusted |
| 7 | `bootstrap.exec`: `execve(command, argv, env)`, cwd = workdir (or `cwd`) entered via `O_NOFOLLOW` walk + `fchdir`, no shell, **no credentials**; leftover descendants are killed → `BootstrapFailed` | **agentd** | **untrusted** |
| 7b | credential copies/staged env placed (runnerd, `O_EXCL`, links never followed) — only after `BootstrapDone`, before `Proceed` (without bootstrap: at step 5) | runnerd | trusted |
| 8 | launch the harness as an ACP stdio agent, cwd = workdir → `Ready` | agentd | untrusted |
| 9 | gateway listens → authenticated raw ACP | runnerd | trusted relay |

runnerd never executes anything a caller, bundle or harness supplied: bundles are data,
`bootstrap.exec` is delivered to agentd in the launch spec and runs there (the test proves the
parent process of a bootstrap command is `agentd`). After the exec steps agentd reports
`BootstrapDone` and waits for `Proceed`; runnerd fingerprints the workspace before and after,
and the paths changed by setup are excluded from the artifact (`bootstrap.execArtifactPolicy`,
default `exclude`) — setup output is runtime state, not work. Credential copies land only
in step 7b, after the untrusted steps finished: a bootstrap step can neither receive
credential variables nor read the files (V4; without bootstrap the order is unchanged).
agentd is a child subreaper and kills anything a step left behind — survivors fail the
bootstrap (`BootstrapFailed`, "left background processes") instead of living on into the
harness lifetime, when the credentials arrive.

Code: `bins/runnerd/src/bootstrap.rs` (trusted steps), `bins/runnerd/src/home.rs`
(`replace_beneath`, `resolve_dir_beneath`, `symlink_beneath`), `bins/agentd/src/main.rs`
(`run_bootstrap`), `crates/acp-runner-core/src/attempt_spec.rs` (`BootstrapPlan`).

## 3. Bundles and the thin harness adapter

`BundleProvider::resolve(kind, name) → Bundle{files[], metadata, digest}`
(`crates/acp-runner-engine/src/bundles.rs`: `DirBundleProvider` over `configs/ agents/ skills/`,
`StaticBundleProvider`). The core is format-agnostic; the harness adapter's *data half*
(`crates/acp-runner-core/src/harness.rs`) only maps (harness, kind, name) to a directory:

| harness | agent | skill | config |
|---------|-------|-------|--------|
| claude  | `~/.claude/agents/` | `~/.claude/skills/<name>/` | `<workdir>/` (CLAUDE.md) |
| codex   | `~/.codex/agents/<name>/` | `~/.codex/skills/<name>/` | `<workdir>/` (AGENTS.md) |
| other   | `~/.acp/agents/<name>/` | `~/.acp/skills/<name>/` | `<workdir>/` |

The *process half* (probe, launch argv, ACP transport, shutdown) stays in
`acp-runner-drivers` under agentd; `AgentDriver::acp_spawn` gives the ACP stdio launch.
Harnesses that are not ACP agents get a small wrapper instead of provider hacks: Claude Code
runs behind `agentd claude-acp-bridge` (`crates/acp-runner-drivers/src/claude_acp.rs`), which
drives the unmodified `claude -p` stream-json per turn (`--session-id`, then `--resume`), keeps
the `apiKeySource` guard, and maps to `session/update` / `stopReason`. Multi-turn Claude
environments work through it.

Two filesystem inputs stay distinct: **overlays** are inherited work and belong to the
artifact; **bootstrap files / config bundles** are runtime configuration, excluded by default
(`CollectOptions.exclude_paths`: excluded paths keep their base content in the artifact's view,
so an injected `CLAUDE.md` never reaches the user's patch, even if it replaced a repo file).

## 4. Lineage, branch, review

Artifacts are cumulative against the original base: `S1 = diff(base, S1)`,
`B1 = diff(base, B)`. Lineage is metadata (`artifacts.environment_id`, `parent_artifact_id`,
`parent_environment_id`, derived server-side at upload; migration `0005_v3_bootstrap.sql`).

`branch(artifactId, overrides)` = `create` with `workspace.overlays: [{type: patchArtifact}]`
and the origin environment's spec (overrides: harness, agents, skills, configs, credentials,
lifetime, bootstrap, output, workdir, env). The provider fetches the artifact metadata, verifies
the content hash, resolves the origin's repository and pins it to the artifact's base; runnerd
checks the base and the sha256 again before `git apply`. Review needs no new primitive:

```
implement (A) ── snapshot S1 ──┬── review  = branch(S1, {configs: [reviewer], output: none, lifetime: 10 min})
                               └── fix     = branch(S1)  → F1 = diff(base, F), parent S1 / A
```

The orchestrator never handles patch bytes. `snapshot_and_wait()` returns the snapshot's
artifact id for branching.

## 5. Raw ACP dataplane + restart-safe tickets

```
GET /v1/acp HTTP/1.1
Authorization: Bearer act1.<claims>.<mac>
Upgrade: acp-ndjson | websocket

HTTP/1.1 101 Switching Protocols
X-ACP-Environment: <id>   X-ACP-Workdir: <cwd for session/new>   X-ACP-Phase: Idle
<newline-delimited JSON-RPC>  |  <one JSON-RPC message per WebSocket text frame>
```

After the upgrade the gateway relays bytes to the harness (via agentd's data socket) and back,
unmodified; it knows only "this connection belongs to environment X". New ACP methods need no
runnerd change (a test sends an extension method runnerd has never heard of). runnerd reads
along passively (`bins/runnerd/src/tap.rs`) for Idle/Busy and the journal; the old
Attach/Prompt/Cancel/Ping frames are gone. One caller at a time: a newly authenticated
connection replaces the previous one; a harness request with no caller attached gets a generic
JSON-RPC error instead of hanging.

Tickets (`crates/acp-runner-core/src/ticket.rs`): `{env, aud, exp, nonce}` MAC'd with
`K_env = HMAC-SHA256(provider_master_key, "acp-runner/gateway-key/v1/" ‖ env)`. runnerd of X holds
only `K_env(X)` (per-attempt Secret `gateway-key`): it can verify tickets for X and nothing else;
a ticket for A fails on B's gateway before the claims are read. Tickets are short-lived
(default 300 s, max 3600 s), single-use (nonce), never stored anywhere; a restarted provider
re-derives `K_env` and issues new tickets for environments that outlived it (tested).
`TicketKey::from_file` loads the master key from a Secret. CRD status, events and the journal
never contain tickets (tested).

Clients: `crates/acp-runner-client` (raw + WebSocket transports, plain ACP client).

## 6. Credential lease for the environment lifetime

create → `start_attempt(lease)` (exclusive profiles: `max_concurrent_leases = 1`; a second
environment on the same profile fails with `ProviderError::CredentialBusy`) → runnerd places
ephemeral copies → every runnerd heartbeat extends the lease (`Journal::extend_lease`, never
shortens) → the environment ends → runnerd hands refreshed files back (validated write-back,
now accepted because the attempt holds the lease) → the provider releases the lease
(`finalize`). A dead sandbox's lease lapses after `credential_lease_window`.

## 7. One runtime image, harness artifacts

`HarnessProvider::resolve(name, version) → HarnessArtifactRef{digest, executable, adapter,
driverConfig, path, manifest}` (`crates/acp-runner-engine/src/harness.rs`,
`DirHarnessProvider`: `<root>/<name>/<version>/{manifest.json, harness.tar.gz}`; the manifest
carries the pin and the provider refuses an archive with another digest). The ingest serves only
the artifact the attempt pins; runnerd verifies the digest again and extracts (no absolute or
`..` paths, in-tree relative symlinks only, no devices/hard links, setuid/sgid and
group/world-write bits dropped, `O_NOFOLLOW` writes) into `/opt/harness` — an emptyDir that is
read-write for runnerd and **read-only for agentd**. `{harness}` in the manifest's driver config
and `path` entries are resolved to the agent's view. The runner image can be built without CLIs
(`--build-arg WITH_CLIS=0`); image-installed CLIs remain the fallback when no provider
resolves the harness.

## 8. OpenAI Responses shim (outside the core)

`bins/acp-openai-shim`: `POST /v1/responses` (text / `input_text` input, `instructions`,
`stream` → SSE `response.*` events, `previous_response_id` → same ACP session),
`GET /v1/responses/{id}`, `POST /v1/responses/{id}/cancel` (ACP `session/cancel`),
`GET /v1/models`; `usage` when the agent reports it. `model` names the environment via a
`ConnectionSource` (the provider, or a connections file refreshed by a sidecar — the shim never
holds the ticket key). Client function tools are refused in v1 (`unsupported_tools`); the
harness's own tools run inside the environment.

## 9. Files

New: `crates/acp-runner-core/src/{ticket,bundle,harness}.rs`, `crates/acp-runner-client/`,
`crates/acp-runner-drivers/src/claude_acp.rs`, `bins/runnerd/src/{bootstrap,tap}.rs`,
`crates/acp-runner-engine/src/{bundles,harness}.rs`, `bins/acp-openai-shim/`,
migrations `0004_v3_dataplane.sql`, `0005_v3_bootstrap.sql`, tests
`bins/runnerd/tests/bootstrap.rs`, `bins/runnerd/tests/common/env_mode.rs`,
`bins/acp-openai-shim/tests/shim.rs`, `deploy/examples/agentenvironment-review.yaml`.

Changed: `environment.rs` (core spec v3), `attempt_spec.rs` (`BootstrapPlan`, `SessionMode`
without token hash), IPC (`raw_acp`, `workdir`, `bootstrap`, `path_prepend`, `BootstrapDone`,
`Proceed`; `Prompt`/`TurnEnded` removed), agentd (raw session, bridge, bootstrap exec), runnerd
environment supervisor + gateway, workspace crate (`prepare_empty`, exclusions, fingerprints),
engine provider (tickets, resolution, branch, leases, finalize) + ingest (bootstrap downloads,
lineage, lease renewal), journal (lineage, bundles, `extend_lease`), pod (`/opt/harness`),
CRD + regenerated `deploy/crds/acp-runner.dev_crds.yaml`, runner Dockerfile. `WIRE_VERSION` = 3.

## 10. Tests (executed in this environment)

`cargo test --workspace` with PostgreSQL 16 (`ACP_TEST_DATABASE_URL`) and a controller-runtime
envtest kube-apiserver v1.37 (`ACP_E2E_KUBECONFIG`), as root (namespace isolation suite):
**212 passed, 0 failed, 0 skipped**; `cargo clippy --workspace --all-targets -D warnings` and
`cargo fmt --check` clean. v3-specific coverage:

| requirement | test |
|---|---|
| raw ACP over HTTP upgrade and WebSocket; multi-turn; snapshot; finish closes | `runnerd environment::{raw,websocket}_acp_two_turns_snapshot_and_finish` |
| gateway transparent for unknown ACP methods | `environment::gateway_relays_acp_methods_it_does_not_know` |
| tickets: garbage, expired, replayed, foreign env; nothing leaked | `environment::gateway_denies_bad_expired_replayed_and_foreign_tickets`, core `ticket::tests` |
| provider restart keeps environments connectable; wrong key refused | `environment_provider::provider_restart_keeps_the_environment_connectable` |
| Claude Code multi-turn via the ACP bridge (`--resume`) | `environment::claude_code_multi_turn_through_the_acp_bridge` |
| workdir = cwd of probe/exec/session/tools; escapes refused | `bootstrap::workdir_bundles_and_untrusted_exec`, `…_refused`, `environment_provider::workdir_is_the_harness_cwd_through_the_provider`, core `normalize_workdir` |
| bundles verified + placed; injected config excluded from artifact | `bootstrap::workdir_bundles_and_untrusted_exec`, `environment_provider::implement_review_fix_is_just_branching`, workspace `excluded_paths_keep_their_base_content_in_the_artifact` |
| bootstrap.exec runs in agentd, no credentials, execve (no shell fallback), failures fail | `bootstrap::workdir_bundles_and_untrusted_exec`, `bootstrap::tampered_bundles_bad_workdirs_and_failing_exec_are_refused` |
| overlays: sha256 + base verified; cumulative artifacts; lineage | `bootstrap::overlays_are_verified_and_artifacts_stay_cumulative`, `environment_provider::provider_verifies_overlay_hash_and_base`, `…implement_review_fix_is_just_branching` |
| review = short branch, output none | `environment_provider::implement_review_fix_is_just_branching`, `bootstrap::output_policy_none_produces_no_final_artifact` |
| inference-only (empty base) is branchable | `bootstrap::inference_only_environment_uses_the_deterministic_empty_base` |
| environment-lifetime exclusive lease, renewal, write-back, release | `environment_provider::environment_holds_an_exclusive_credential_lease_for_its_lifetime` |
| pinned harness artifacts: materialized, digest mismatch / tamper refused, agent RO | `bootstrap::pinned_harness_artifact_is_verified_and_materialized`, `environment_provider::harness_provider_materializes_pinned_artifacts`, runnerd `bootstrap::tests::archives_extract_safely`, k8s `pod::tests::secret_and_private_state_are_mounted_into_runnerd_only` |
| CRD v3 accepted by a real apiserver; bad overlay type rejected | `kube_e2e::controller_end_to_end_on_a_real_apiserver`, k8s `crds::tests::agent_environment_v3_example_converts` |
| OpenAI shim: text, SSE stream, continuation, cancel, tools refused | `acp-openai-shim tests/shim.rs::openai_responses_over_acp` |
| v2 + AgentEnvironment regressions (trust split, isolation, egress, one-shot, fallback) | unchanged suites, all passing |

Harnesses in these tests are the deterministic fakes (ACP agent, Codex CLI + codex-acp
emulation, Claude Code stream-json emulation). Live Codex/Claude accounts were not available in
this session; the live compatibility targets (`ACP_COMPAT_TARGETS=codex,claude`) are unchanged
and were not re-run.

## 11. Limitations and deferred work

* The `AgentEnvironment` **controller reconcile loop** and the per-environment gateway
  **Service** are still not wired: the provider is a library (engine) used by tests, the shim and
  embedders; the CRD is validated against a real apiserver but nothing reconciles it yet.
* Idle/Busy is observed passively from the ACP stream (the harness' own claim); snapshots are
  consistent only at Idle.
* One ACP client per environment at a time (takeover on reconnect). The shim serializes turns
  per environment and keeps its conversation map in memory.
* Setup-output attribution: paths changed by `bootstrap.exec` are excluded as a whole; a later
  agent edit to such a path is excluded too (`execArtifactPolicy: include` opts out).
* Codex agent/skill directories in the harness layout are a convention of this repo, not a
  documented Codex feature; adapters own that mapping and can change it without core changes.
* Harness artifacts come from a directory provider; an OCI-registry provider (pull by digest)
  is the obvious next `HarnessProvider`.
* Tickets use a per-environment HMAC key instead of asymmetric signatures (runnerd X could mint
  tickets for X, which grants nothing it does not already control).
* The OpenAI shim does not support client function tools, images, or persistent conversation
  state across shim restarts.
