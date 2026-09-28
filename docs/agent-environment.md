# AgentEnvironment refactor — lifecycle map, plan, migration

> v3 update: the provider/bootstrap layer (raw ACP dataplane, tickets, bootstrap, workdir,
> bundles, lineage/branch, leases, harness artifacts, OpenAI shim) is described in
> `docs/v3-provider-bootstrap.md`.

This document is the required "map current lifecycle → smallest coherent refactor → backwards
compatibility" analysis for turning acp-runner from a one-shot *task runner* into a general
**agent execution environment provider**, on top of the v2 runnerd/agentd trust split.

## 1. Current lifecycle (v2, before this refactor)

```
ACPRun (CRD)                                 acp-runner-core::spec::RunSpec
   └─ controller (bins/acp-runner-controller) reconciles → engine
        └─ engine (crates/acp-runner-engine) plans attempts, leases credentials
             └─ SandboxBackend.create → Pod {runnerd, agentd}          (crates/acp-runner-k8s)
                  ├─ runnerd (trusted): fetch AttemptSpec (ingest, token), posture,
                  │    git workspace @exact rev + private git dir, synthetic HOME + creds,
                  │    launch agentd, journal events, ONE prompt, timeouts, collect PATCH,
                  │    credential write-back, terminal attempt event
                  └─ agentd (untrusted): run the driver/CLI, ACP/stream-json, forward events
        └─ journal (crates/acp-runner-journal, PostgreSQL): runs, attempts, session_events,
             artifacts, credential_profiles, credential_leases
```

The unit of work is: `bootstrap → one ACP prompt turn → patch → destroy`. The prompt is part
of the `AttemptSpec` and `runnerd` sends exactly one, then collects the patch and exits.

## 2. What stays unchanged (reused as-is)

Almost everything below `runnerd`'s "one prompt" step is reused verbatim:

| Component | Reused for |
|---|---|
| `acp-runner-workspace` | exact-revision bootstrap, **private git dir**, binary patch collection, symlink/size/allowed-path checks → snapshots and the final changeset |
| `acp-runner-drivers` + `agentd` | harness execution (ACP for fake/codex, stream-json for claude), version probing |
| `acp-runner-ipc` | runnerd ↔ agentd protocol (Launch/Cancel/Event/…); extended, not replaced |
| credential model (`core::credentials`, engine `creds`, `home.rs`, K8s Secret store) | `resolve(profile, harness) → bundle`, ephemeral copy, validated write-back |
| Pod hardening (`k8s::pod`), backends, NetworkPolicy, egress proxy | the environment Pod is the same two-container hardened pod |
| journal, artifacts, metrics, redaction | events, snapshots and final artifacts |
| retry/fallback/resume-capsule (`core::plan`, engine) | the **compatibility wrapper** only |

## 3. The change

A new primitive is added *beside* the run/attempt one, not replacing it:

```
AgentEnvironment (durable, provider-facing)
  Creating → Ready/Idle ⇄ Busy (one ACP turn) ; Idle → snapshot (non-terminal)
  Idle → Finishing → Completed ;  any → Failed (harness/process exit, partial artifact)
```

* The provider **never** decides how many turns a task takes. `end_turn` means *this turn is
  done and the environment is Idle* — never *the environment is finished*.
* `finish()` is explicit and authoritative; the filesystem changeset (not agent prose) is the
  result.
* Conversational text ("I can continue…") is never a control signal.

New/changed modules:

| Module | Role |
|---|---|
| `core::environment` | `EnvironmentSpec`, `HarnessSpec`, `EnvironmentPhase` state machine, control/result types (provider-neutral; no Kubernetes concepts) |
| `ipc` `gateway` frames | caller ↔ runnerd session transport (Attach/Prompt/Cancel ↔ Ready/Event/TurnEnded/Closed), env-scoped token; transport-agnostic (a line-framed TCP impl now, WebSocket later) |
| `runnerd::environment` | environment supervisor: bootstrap → Ready, host the gateway, run multiple turns via agentd, honour Snapshot/Finish/Cancel directives, collect snapshot/final patches |
| `engine::environment` | `EnvironmentEngine` = the provider: create/get/connect(issue token)/snapshot/finish/cancel, backed by new journal tables; exposes status/events/artifacts (never raw PostgreSQL) |
| `engine::compat` | `execute(repo, rev, prompt, class)` = create → connect → prompt → wait end_turn → finish, so existing one-shot flows keep working |
| `k8s::crds` `AgentEnvironment` | new CRD (spec/status) beside `ACPRun`; connection tokens never in status |
| journal migration `0003` | `environments`, `env_snapshots` tables; `environment_id` on `session_events`/`artifacts` |

Harness model: the runner image already carries `runnerd`, `agentd`, git, tini, certs and the
pinned CLIs. `HarnessSpec { name, version, config }` selects which CLI/adapter agentd runs; the
existing `AgentDriver` registry is the harness abstraction (evolved, not replaced). Distributing
harnesses as OCI artifacts is left as a boundary (the driver picks the command/adapter), not
implemented now.

## 4. Gateway / remote ACP access

```
caller ──(authenticated stream, env-scoped token)── runnerd gateway ──(local IPC)── agentd ──(ACP stdio)── CLI
```

The gateway authenticates the caller, authorizes exactly one environment, routes a bidirectional
stream and observes session state; it invents no agent semantics. The environment-scoped access
credential is **distinct** from the ingest attempt token and from provider (Claude/Codex)
credentials, and is not stored in CRD status. The transport is isolated behind the
`ipc::gateway` frame codec so ACP is not coupled to a specific network transport; the first
implementation is length-framed JSON over TCP (a WebSocket adapter can wrap the same codec).

Snapshot and finish are provider-authoritative, not caller-ACP and not agent: they travel on the
existing controller→runnerd heartbeat-directive channel (`RunnerDirective::Snapshot/Finish`),
keeping every authoritative action on runnerd's side of the trust boundary. The queue is
durable (`environment_directives`, V5a): deliveries carry a row id, runnerd acks consumed
directives on the next heartbeat, unacked rows are redelivered, cancel is answered before
the queue, and runnerd dedupes redelivered snapshots by `snapshotId`. Environment state
reads (`refresh`, `snapshot_and_wait`) use targeted indexed queries, never full-attempt
scans (V5b).

## 5. Backwards compatibility

* `ACPRun` / `RunSpec` / the engine's run+attempt path are kept and still pass all v2 tests.
* `execute()` (the compatibility wrapper) reproduces the old one-shot semantics on the new
  primitive; retry/fallback/resume stays in that orchestration layer, off by default (one
  environment, no automatic fallback/retry unless requested).
* Default posture is unchanged and conservative.

## 6. Implemented now vs deferred

**Implemented now:** `core::environment` types + state machine; `ipc::gateway` codec; runnerd
environment mode (bootstrap → Ready, multi-turn for ACP harnesses, snapshot at Idle, finish,
partial artifact on failure) with the gateway server; `EnvironmentEngine` provider with
env-scoped tokens; journal tables; compatibility wrapper; `AgentEnvironment` CRD types; tests
1–15 (see README §"AgentEnvironment").

**Deferred (documented):** raw byte-exact ACP-frame passthrough through the gateway (the codec
carries normalized turn control + events today); Claude Code multi-turn in one process
(single turn per process for now — a second turn starts a fresh harness process; ACP harnesses
are genuinely multi-turn); a WebSocket transport adapter; OCI-artifact harness distribution;
live snapshot while Busy (rejected/queued to Idle as specified).
