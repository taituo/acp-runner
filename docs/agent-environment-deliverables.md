# AgentEnvironment — deliverables

> Superseded in parts by v3 (`docs/v3-provider-bootstrap.md`): the gateway now carries raw ACP
> behind signed connection tickets (the Attach/Prompt/Cancel/Ping frames below are gone),
> environments hold exclusive credential leases for their lifetime, skills are real bundles,
> and Claude Code environments are multi-turn through the ACP bridge.

The eight items the task asks for at the end. Companion to `docs/agent-environment.md`
(lifecycle map + refactor plan) and the v2 trust-split docs in the top-level `README.md`.

## 1. Architecture summary

```
orchestrator / caller
      │  provider API (create / get / connect / snapshot / finish / cancel)
      ▼
EnvironmentProvider (crates/acp-runner-engine::environment)
      │  one long-lived attempt + environments table; env-scoped tokens; status/events/artifacts
      ▼
SandboxBackend  →  Pod {runnerd (trusted), agentd (untrusted)}   (or LocalProcessBackend)
      │
   runnerd env mode (bins/runnerd::environment)
      ├─ trusted bootstrap: git @exact rev + private git dir, synthetic HOME + creds + skills
      ├─ ACP gateway (bins/runnerd::gateway): env-scoped token, one environment, routes prompts/events
      ├─ multi-turn via agentd (interactive); snapshot/finish/cancel via heartbeat directives
      └─ trusted collector: BASE-relative binary patch (snapshots + final), credential write-back
```

`end_turn` → Idle (not finished). `finish()` is explicit and authoritative; the filesystem
changeset, computed by runnerd against the trusted base, is the result — never the agent's prose.
The gateway invents no agent semantics (authenticate, authorize one environment, route the
stream, observe state). The environment-scoped access token is distinct from the ingest token
and from Claude/Codex credentials, and is never stored in CRD status.

## 2. Files / modules changed

New:
- `crates/acp-runner-core/src/environment.rs` — EnvironmentSpec/HarnessSpec, EnvironmentPhase.
- `crates/acp-runner-ipc/src/lib.rs` `gateway` module — caller↔runnerd frame codec.
- `bins/runnerd/src/environment.rs` — environment supervisor; `bins/runnerd/src/gateway.rs` — ACP gateway.
- `crates/acp-runner-engine/src/environment.rs` — EnvironmentProvider; `.../compat.rs` — one-shot wrapper.
- `crates/acp-runner-journal/migrations/0003_environments.sql` + journal env rows/methods.
- `crates/acp-runner-k8s/src/crds.rs` — `AgentEnvironment` CRD (spec/status) + `to_core`.
- `bins/agentd/src/main.rs` — interactive multi-turn (Ready/TurnEnded, per-prompt turns, soft cancel).
- Tests: `bins/runnerd/tests/environment.rs`, `crates/acp-runner-engine/tests/environment_provider.rs`.
- Docs: `docs/agent-environment.md`, this file; `deploy/examples/agentenvironment-codex.yaml`.

Changed (reused): `attempt_spec.rs` (SessionMode, SkillMount), `events.rs`
(RunnerDirective::Snapshot/Finish), engine `ingest.rs` (env directives + snapshot/final
artifact kinds), `lib.rs` module wiring, `crds_yaml`/crdgen (3 CRDs).

## 3. Migration from ACPRun

`ACPRun` / `ACPRunnerClass` and the run/attempt engine are unchanged and still pass every v2
test. `AgentEnvironment` is added beside them; an environment is backed internally by one
long-lived attempt, so the journal, ingest, sandbox backends, workspace collector, credential
model and Pod hardening are reused verbatim. The classic one-shot behaviour is available through
`engine::compat::execute()` (create → connect → prompt → wait end_turn → finish); retry/fallback/
resume stay in the run/attempt engine (the conservative default is one environment, no automatic
fallback or retry). No resource is deleted; callers migrate to `AgentEnvironment` at their pace.

## 4. New CRD/API example

`deploy/examples/agentenvironment-codex.yaml` (full example). Shape:

```yaml
apiVersion: acp-runner.dev/v1alpha1
kind: AgentEnvironment
spec:
  externalRef: task-1234
  harness: {name: codex, version: "0.156.1", config: {mode: agent-full-access}}
  repository: {url: https://…, revision: <40-hex>}
  credentials: {profile: personal-1}
  skills: [rust-backend, company-conventions]
  egress: {mode: proxy, httpsProxy: http://acp-egress-proxy.acp-egress.svc:3128}
  idleTimeoutSeconds: 1800
status:
  phase: Creating|Idle|Busy|Finishing|Completed|Failed
  environmentId: …
  harness: {name: codex, version: …}
  resolvedRevision: …
  connection: {gateway: "<reference only; token issued out of band>"}
  latestSnapshotRef: {artifactId: …}
  finalArtifactRef: {artifactId: …, sha256: …, baseRevision: …}
  failureReason: {code: …, message: …}
```

Provider API (verified in tests): `create(spec) → view(Creating)`, `connect(id) → {gateway,
token}` (env-scoped), `snapshot(id, label) → snapshotId`, `finish(id) → view(Completed,
finalArtifact)`, `cancel(id, reason)`, `get(id) → view` (phase, connection ref, snapshots,
final artifact, failure).

## 5. Security-impact summary

Preserved from v2 (unchanged): two-container hardened pod, Secret only in runnerd, non-root,
read-only rootfs, no caps/privilege-escalation, no SA token, seccomp, optional gVisor, egress
modes + allowlisting proxy for credentialed classes, private authoritative git dir, ephemeral
credential copies + validated write-back, `O_NOFOLLOW` credential placement/read-back, redaction.

New surface and its containment:
- **Gateway** adds an inbound port. It requires an environment-scoped bearer token (sha256 in
  the spec; value issued by the provider, never in CRD status/events), authorizes exactly one
  environment id, and rejects everything else (proven: bad token, wrong/other environment id,
  cross-environment token). It carries prompts/events only — it cannot submit terminal state,
  artifacts or heartbeats (those stay on runnerd's authoritative path).
- **Multi-turn** does not widen agent authority: each turn is the same untrusted agentd turn;
  snapshot/finish/cancel are provider operations on the heartbeat channel, never agent- or
  caller-driven control of the lifecycle.
- **Snapshots/final** are computed by runnerd from the trusted base (agent `.git` tampering is
  ignored), size/symlink/allowed-path checked, and never trust agent-generated patches.

## 6. Tests added and results

Run in the authoring environment (Rust 1.95, PostgreSQL 16, controller-runtime envtest
kube-apiserver/etcd v1.37, git 2.43, Node 22; namespaces available as root):

| # | Requirement | Proven by | Result |
|---|---|---|---|
| 1 | environment created reaches Ready | `environment_provider::provider_create_connect_turns_snapshot_finish`, `environment::create_connect_two_turns_snapshot_and_finish` | pass |
| 2 | harness starts + connect through the session layer | same (gateway Attach → Attached) | pass |
| 3 | one ACP turn completes, environment survives | same | pass |
| 4 | second ACP turn in the same environment | same (ACP multi-turn) | pass |
| 5 | snapshot at Idle → valid patch, env alive | same (`snapshot_created`, snapshot artifact) | pass |
| 6 | later modification → updated BASE-relative snapshot | same (turn 2 + second snapshot has the new file) | pass |
| 7 | finish → final patch + environment destroyed | same (Completed, `final` artifact, sandbox released) | pass |
| 8 | unexpected harness exit → Failed + partial artifact | `environment::unexpected_harness_exit_fails_with_partial_artifact` | pass |
| 9 | `.git/config` tampering doesn't corrupt collection | `acp-runner-workspace::tampered_git_config_is_neutralized`, `…agent_rewriting_its_git_dir_does_not_affect_collection` | pass |
| 10 | new/untracked + binary files captured | `acp-runner-workspace::prepare_modify_collect_and_apply`, `runnerd security::sparse_and_binary_and_commit_scenarios`, env snapshot of untracked `extra.txt` | pass |
| 11 | credentials not exposed via status/events | `environment::gateway_denies_…` (secrets absent from events), provider view has no token | pass |
| 12 | remote ACP denied without env-scoped auth | `environment::gateway_denies_bad_token_and_cross_environment_token` | pass |
| 13 | token for env A cannot connect to env B | same + `environment_provider::provider_denies_cross_environment_token` | pass |
| 14 | one-shot via the compatibility wrapper | `environment_provider::compat_wrapper_runs_one_shot_and_produces_the_patch` | pass |
| 15 | Kubernetes security invariants intact | `acp-runner-k8s::pod::*`, `controller kube_e2e` (hardened two-container pod, RBAC denial) | pass |

Full workspace (`cargo test --workspace` with `ACP_TEST_DATABASE_URL` + `ACP_E2E_KUBECONFIG`)
passes; `cargo clippy --workspace --all-targets -D warnings` and `cargo fmt --check` are clean.

## 7. Remaining limitations

- Gateway carries normalized turn-control + events, not byte-exact ACP frame passthrough.
- Claude Code is single-turn-per-process (a second turn would start a fresh harness); ACP
  harnesses (fake, codex) are genuinely multi-turn.
- Snapshots are guaranteed only at Idle; a snapshot requested while Busy is rejected (no live
  filesystem freeze).
- The `AgentEnvironment` **controller reconcile loop** and the in-cluster gateway **Service** are
  not wired yet: the provider is implemented and tested at the engine level (LocalProcessBackend
  and, for hardening, envtest). Pod-mode gateway exposure needs a Service per environment.
- Codex environments load the credential without the exclusive-lease serialization the one-shot
  path uses (documented; safe for a single environment).
- No WebSocket transport adapter yet (the codec is transport-agnostic for one).

## 8. Implemented now vs deferred

**Now:** the primitive and its state machine; interactive multi-turn agentd; runnerd env mode +
gateway; snapshot/finish/cancel; EnvironmentProvider (create/get/connect/snapshot/finish/cancel)
with env-scoped tokens and status/events/artifacts through the provider boundary; compat
one-shot wrapper; `AgentEnvironment` CRD + example; journal migration; all 15 checks.

**Deferred (documented above):** AgentEnvironment controller reconcile + gateway Service;
raw-ACP passthrough; Claude multi-turn-in-process; WebSocket transport; OCI-artifact harness
distribution; exclusive credential leases for environments; snapshot-while-Busy.
