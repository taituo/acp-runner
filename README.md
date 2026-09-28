# acp-runner

> **Status:** the controller reconciles `ACPRun` resources only — the
> `AgentEnvironment` reconcile is not wired up yet (V10). Environments are
> driven through the provider API (tests, dev-run), not by the controller.

A vendor-agnostic Kubernetes execution layer for Linux coding-agent CLIs.

```text
task ─▶ isolated agent runtime ─▶ CLI ─▶ observable session ─▶ patch artifact / failure
```

acp-runner takes a task (repository + exact revision + prompt), runs one coding-agent CLI
(OpenAI Codex or Anthropic Claude Code today) in a disposable, hardened sandbox, journals a
normalized event stream, and returns a binary-capable git patch against the input revision —
or a precise failure. It retries and falls back to other runner classes. It never pushes,
merges or opens pull requests, and it does not decide *what* agents work on: it is the
lowest layer below an orchestrator.

The orchestrator never needs to know how a CLI is installed, authenticated, started,
supervised or sandboxed. It creates an `ACPRun` and reads its status, journal and artifact.

Two runtime primitives share this machinery:

* **One-shot `ACPRun`** (above): bootstrap → one prompt turn → patch → destroy.
* **Multi-turn `AgentEnvironment`**: bootstrap → Ready → *many* ACP turns over an authenticated
  gateway, non-terminal `snapshot()`s, explicit authoritative `finish()`. See
  `docs/agent-environment.md` (design), `docs/agent-environment-deliverables.md` (summary,
  CRD, security, test map) and `deploy/examples/agentenvironment-codex.yaml`.
* **v3 provider/bootstrap layer** (`docs/v3-provider-bootstrap.md`): bootstrap as data
  (trusted file placement in runnerd, untrusted `execve` setup in agentd), first-class
  `workspace.workdir`, config/agent/skill bundles, workspace overlays + lineage + `branch()`
  (review = a short branch), **raw ACP** over HTTP upgrade / WebSocket behind signed,
  restart-safe connection tickets, environment-lifetime credential leases, pinned harness
  artifacts in one runtime image, and an OpenAI Responses shim as a separate ACP client
  (`bins/acp-openai-shim`). Example: `deploy/examples/agentenvironment-review.yaml`.

Inside the sandbox every attempt/environment runs as **two containers**: a trusted `runnerd`
supervisor (attempt token, credentials, workspace, patch collection, journal) and an untrusted
`agentd` executor (the provider CLI), split across trust domains (`docs/agent-environment.md`
§1–4). `acp-runnerctl auth` enrolls credential profiles; `deploy/egress-proxy/` restricts
egress for credentialed runs.

---

## Contents

1. [Status and what was verified](#1-status-and-what-was-verified)
2. [Architecture](#2-architecture)
3. [Repository layout](#3-repository-layout)
4. [Quick start without Kubernetes](#4-quick-start-without-kubernetes)
5. [Build](#5-build)
6. [Deterministic tests](#6-deterministic-tests)
7. [KIND walkthrough](#7-kind-walkthrough)
8. [Credentials: enrollment, leases, storage](#8-credentials-enrollment-leases-storage)
8b. [Trust model: who may use credentials](#8b-trust-model-who-may-use-credentials-v2)
9. [Authentication findings (verified 2026-09-26)](#9-authentication-findings-verified-2026-09-26)
10. [Live smoke tests (opt-in)](#10-live-smoke-tests-opt-in)
11. [Runner image, version pinning and upgrades](#11-runner-image-version-pinning-and-upgrades)
12. [Kubernetes model](#12-kubernetes-model)
13. [Sandbox and filesystem security](#13-sandbox-and-filesystem-security)
14. [Network model and its actual guarantees](#14-network-model-and-its-actual-guarantees)
15. [Runtime internals](#15-runtime-internals)
16. [Observability](#16-observability)
17. [Drivers and how to add one](#17-drivers-and-how-to-add-one)
18. [Security test map](#18-security-test-map)
19. [Findings, incompatibilities and limitations](#19-findings-incompatibilities-and-limitations)
20. [Definition-of-done map](#20-definition-of-done-map)

---

## 1. Status and what was verified

Prototype (`v1alpha1`), built to be continued, not thrown away.

Executed in the authoring environment (Linux x86_64, Rust 1.95, PostgreSQL 16,
kube-apiserver/etcd v1.37 from the controller-runtime envtest bundle, git 2.43, Node 22):

| Area | Evidence |
|---|---|
| Unit tests (core, ACP client, drivers, workspace, k8s builders, metrics) | `cargo test --workspace` |
| PostgreSQL journal: append-only trigger, idempotent events, advisory locks, exclusive/expiring credential leases, supervision-lease takeover, artifact store limits | `crates/acp-runner-journal/src/tests.rs` |
| Engine end-to-end with real runnerd processes + fake agent: success, retry, fallback, no-progress timeout, sandbox disappearance, frozen runnerd (heartbeat loss), stale controller takeover, exclusive lease + validated credential write-back, cancellation, oversized artifact, apply-previous-patch | `crates/acp-runner-engine/tests/e2e.rs` (13 tests) |
| **Kubernetes end-to-end against a real kube-apiserver v1.37**: CRDs, controller, finalizer, hardened Pod + per-attempt Secret, ingest, runnerd, fake agent, status, retry+fallback, Secret-backed credential store with write-back, deletion cleanup, agent SA RBAC denial, `Sandbox` objects accepted by the upstream agent-sandbox **v1beta1** CRD schema | `bins/acp-runner-controller/tests/kube_e2e.rs` (a simulated kubelet runs the pods' runnerd locally) |
| Driver compatibility suite with the fake ACP agent and a fake Claude stream-json CLI | `bins/runnerd/tests/compat.rs` |
| **Real `@agentclientprotocol/codex-acp` 1.13.1 + `@openai/codex` 0.156.1/0.157.1 without credentials**: version detection, `codex login status` classification, ACP v1 `initialize`, `session/new` → `-32000 Authentication required` → `AuthEnrollmentRequired` | `ACP_COMPAT_TARGETS=codex-noauth` |
| CLI upgrade flow (`scripts/upgrade-cli.sh codex 0.157.1`: pin → lock → candidate → suite → status) | run on a copy of the repo |
| Enrollment UX with scripted stand-ins for the provider CLIs (whitelist capture, no secret echo, API-key refusal) | `bins/acp-runnerctl/tests/cli.rs` |
| `dev-run` demo (fallback run, journal, patch) | `scripts/dev-run.sh` |

**Not executed in the authoring environment** (its egress policy blocked all container
registries, so no base image could be pulled): building the container images, the KIND
walkthrough (`scripts/e2e-kind.sh`), the in-image contract smoke (`scripts/compat-image.sh`)
and live subscription smoke tests. These are scripted and wired into CI
(`.github/workflows/ci.yml`); treat their first run as the acceptance step. No real Codex or
Claude subscription login was used by the author; `drivers.lock.yaml` records exactly what was
verified per driver.

## 2. Architecture

```text
                    ┌──────────────── Kubernetes ───────────────────────────────────────────┐
 orchestrator ──▶   │ ACPRun (CRD)            ACPRunnerClass (CRD)                          │
 (not part of this) │    │ watch/status            │                                        │
                    │    ▼                         ▼                                        │
                    │ acp-runner-controller ── Engine ── PostgreSQL journal                  │
                    │   │  (kube-runtime)        │   runs · attempts · session_events        │
                    │   │                        │   artifacts · credential_profiles/leases  │
                    │   │ SandboxBackend:        │                                           │
                    │   │  Pod | agent-sandbox   │ ingest API (:8081, per-attempt token)     │
                    │   ▼                        ▲                                           │
                    │ ┌──────── attempt sandbox (Pod, optional gVisor) ──────────────────┐   │
                    │ │ tini ─ runnerd ── events/heartbeats/artifact ────────────────────┘   │
                    │ │         │ AgentDriver                                              │   │
                    │ │         ├─ fake   : fake-acp-agent           (ACP v1 / stdio)       │   │
                    │ │         ├─ codex  : codex-acp ─▶ codex app-server (ACP v1 / stdio)  │   │
                    │ │         └─ claude : claude -p stream-json     (native CLI)          │   │
                    │ │ /workspace (tmpfs git worktree)  /home/agent (synthetic HOME)       │   │
                    │ │ /tmp (tmpfs)  /var/run/acp-runner/attempt (ro: token + leased creds) │   │
                    │ └────────────────────────────────────────────────────────────────────┘   │
                    └──────────────────────────────────────────────────────────────────────────┘
```

* **Run** (`ACPRun`, `runs` row): stable, logical, owned by the orchestrator (`taskId`).
* **Attempt** (`attempts` row + one sandbox): disposable. A CLI process never owns the
  canonical identity; provider session ids are journaled for information only.
* **Engine**: backend-agnostic, idempotent reconcile of one run under a PostgreSQL advisory
  lock; plans attempts (retry/fallback), supervises (heartbeat, progress, timeouts, sandbox
  liveness), builds resume capsules, releases leases.
* **runnerd**: in-sandbox supervisor: workspace, synthetic HOME, driver, event
  normalization + redaction, timeouts with graceful→forced termination, patch collection,
  credential write-back.
* **ACP** is used as the *local* protocol between runnerd and the agent (stdio) where the
  agent speaks it; there is no cross-cluster ACP network.

## 3. Repository layout

```text
crates/
  acp-runner-core/       domain model: specs, state machines, failures, retry planner,
                         events, resume capsule, credential whitelists, redaction, paths
  acp-runner-acp/        minimal tolerant ACP v1 client (newline-delimited JSON-RPC)
  acp-runner-client/     ACP client for environment gateways (ticket auth, raw ndjson / WebSocket)
  acp-runner-ipc/        runnerd <-> agentd local protocol (control socket; raw ACP data socket)
  acp-runner-workspace/  git prepare (exact SHA, shallow, sparse) + binary patch collection
  acp-runner-drivers/    AgentDriver/AgentProcess traits; fake, codex (codex-acp), claude drivers;
                         Claude Code ACP bridge (environments)
  acp-runner-journal/    PostgreSQL schema/migrations, repository, artifact store
  acp-runner-engine/     Engine, SandboxBackend (+ LocalProcessBackend), CredentialStore,
                         ingest API, metrics, resume-capsule builder, EnvironmentProvider
                         (create/connect/snapshot/branch/finish), Bundle/HarnessProviders
  acp-runner-k8s/        CRDs, hardened pod builder, PodBackend, AgentSandboxBackend,
                         Secret-backed credential store
bins/
  acp-runner-controller/ controller (`run`), `crdgen`, `dev-run`
  runnerd/               in-sandbox supervisor (`pod`, `local`); environment mode: trusted
                         bootstrap + raw ACP gateway
  agentd/                untrusted executor (CLI driver, bootstrap.exec, `claude-acp-bridge`)
  acp-egress-proxy/      allowlisting CONNECT proxy for credentialed egress
  acp-openai-shim/       OpenAI Responses subset as an ACP client of an environment
  acp-runnerctl/         admin CLI: `auth enroll|list|inspect|…`, `run list|get|events|artifact`
  fake-acp-agent/        deterministic fake agent (ACP) + Claude stream-json emulation
deploy/                  CRDs, controller, agents namespace + NetworkPolicies, dev PostgreSQL,
                         KIND config, gVisor RuntimeClass, egress-proxy example, examples/
images/                  runner (runnerd + git + pinned CLIs) and controller Dockerfiles
scripts/                 dev/test/kind/build/install/compat/upgrade/live-smoke helpers
tests/fixtures/          buggy-repo: tiny repository with a known bug
drivers.lock.yaml        machine-readable driver compatibility matrix
```

## 4. Quick start without Kubernetes

Runs the real engine, ingest API and runnerd processes with the fake agent against the
fixture repository. **No isolation** — only for the fake driver / development.

```bash
eval "$(scripts/dev-postgres.sh)"          # docker compose, or --local (initdb) without Docker
scripts/dev-run.sh deploy/examples/local/acprun-fallback.yaml
# prints journal events as they arrive, the final ACPRun-style status, and writes
# .acp-runner-dev/fake-fallback-1.patch

target/debug/acp-runnerctl run list
target/debug/acp-runnerctl run events fake-fallback-1
target/debug/acp-runnerctl run artifact fake-fallback-1 -o /tmp/fix.patch
```

Other local examples: `acprun-fake.yaml` (success), `acprun-retry.yaml` (crash, then retry
succeeds), `acprun-hang.yaml` (no-progress timeout, then fallback).

## 5. Build

Requirements: Rust 1.95 (`rust-toolchain.toml`), git, a C toolchain; Docker for images;
Node 22 + npm only for the compatibility suite against real CLIs.

```bash
cargo build --workspace            # all components
cargo build --release -p acp-runner-controller -p runnerd -p acp-runnerctl
target/debug/acp-runner-controller crdgen > deploy/crds/acp-runner.dev_crds.yaml   # regenerate CRDs
```

## 6. Deterministic tests

No provider account is needed for anything in this section.

```bash
eval "$(scripts/dev-postgres.sh)"                                        # ACP_TEST_DATABASE_URL
export ACP_E2E_KUBECONFIG=$(ENVTEST_BIN=/path/to/envtest scripts/envtest-up.sh)   # optional
export ACP_E2E_AGENT_SANDBOX_CRDS=/path/to/sandbox-with-extensions.yaml             # optional
scripts/test.sh            # fmt, clippy -D warnings, all unit/integration/e2e tests
scripts/compat.sh          # driver contract suite: fake-acp, fake-claude, codex-noauth
scripts/envtest-down.sh
```

* PostgreSQL-backed tests create and drop a throw-away database per test
  (`acp_test_<uuid>`) through `ACP_TEST_DATABASE_URL`; they print `SKIPPED` without it.
* envtest binaries: `envtest-v1.37.0-linux-amd64.tar.gz` from the controller-tools
  releases (see CI). The Kubernetes e2e test runs attempt pods with a *simulated kubelet*
  (runnerd started locally from the pod's spec/Secret, pod status patched), so it needs no
  container runtime.
* `codex-noauth` needs npm access: `scripts/compat.sh` installs exactly the CLIs pinned in
  `images/runner/package-lock.json` into `.cache/clis`.

## 7. KIND walkthrough

Requirements: Docker, kind ≥ v0.33.0 (its kindnetd enforces NetworkPolicy), kubectl.

```bash
scripts/kind-up.sh                      # cluster "acp-runner"
scripts/build-images.sh --kind          # acp-runner/{runner,controller}:dev, loaded into KIND
scripts/install.sh                      # CRDs, controller + dev PostgreSQL, acp-agents namespace,
                                        # NetworkPolicies, fake runner classes

kubectl apply -f deploy/examples/acprun-fake.yaml       # success
kubectl apply -f deploy/examples/acprun-retry.yaml      # crash on attempt 1, retry succeeds
kubectl apply -f deploy/examples/acprun-fallback.yaml   # crash x2, fallback class succeeds
kubectl apply -f deploy/examples/acprun-hang.yaml       # hung agent -> TimedOut -> fallback
kubectl -n acp-agents get acpruns -w
kubectl -n acp-agents get pods -l app.kubernetes.io/name=acp-runner-agent -w   # attempt lifecycle

eval "$(scripts/port-forward-db.sh)"                    # DATABASE_URL for acp-runnerctl
target/debug/acp-runnerctl run get fake-fallback-1 -n acp-agents
target/debug/acp-runnerctl run events fake-hang-1 -n acp-agents --follow
target/debug/acp-runnerctl run artifact fake-fix-1 -n acp-agents -o fix.patch
```

`scripts/e2e-kind.sh` does all of the above and then checks, inside a live agent pod: no
service-account token, non-root uid, read-only root filesystem, no capabilities,
`no_new_privs`, tmpfs mounts, Kubernetes API unreachable, ingest reachable, and
`kubectl auth can-i get secrets --as=system:serviceaccount:acp-agents:acp-runner-agent` = no.

Simulating failures on a cluster:

| failure | how |
|---|---|
| crashed agent | runner class scenario `crash` / `crash-until:N` |
| hung agent | scenario `hang` (honours cancel) or `hang-hard` (ignores cancel) |
| sandbox disappeared | `kubectl -n acp-agents delete pod <sandbox>` → `SandboxLost` |
| hung runnerd | `kubectl -n acp-agents exec <pod> -- kill -STOP 1`… (or delete the controller's ingest reachability) → `HeartbeatLost` |
| controller crash | `kubectl -n acp-runner-system delete pod -l app.kubernetes.io/name=acp-runner-controller` mid-run; the new instance takes over the supervision lease |

## 8. Credentials: enrollment, leases, storage

**Model.** A *credential profile* is the provider-supported login state produced by one
human enrollment of one independently authorized account. Only a provider **whitelist** of
files/values is stored (never a whole `$HOME`):

| provider | stored key | how the CLI receives it | refresh | lease |
|---|---|---|---|---|
| codex | `auth.json` | ephemeral copy at `$HOME/.codex/auth.json` (`CODEX_HOME`) | Codex refreshes tokens in the copy; runnerd hands the refreshed file back; the controller **validates** it (JSON shape, no API key, same auth mode, same account fingerprint) before updating the store | **exclusive** (one attempt at a time), as required by OpenAI's CI/CD guidance |
| claude | `oauth-token` | env `CLAUDE_CODE_OAUTH_TOKEN` of the `claude` process only | none (one-year token) | configurable concurrency (`--max-concurrent-leases`, default 1) |

A run gets a *lease* (`credential_leases`) on one profile from the runner class' candidate
list, acquired transactionally with the attempt. Leases expire (attempt deadline + margin) so
a crashed controller cannot hold one forever; they are released when the attempt ends. A
provider-reported authentication failure marks the profile `needs_reauth` (API-key detection
marks it `disabled`); re-enrollment re-activates it. Multiple profiles are for independently
authorized credentials — this is **not** an account-rotation mechanism for usage limits:
the engine never switches profile because of rate limiting.

**Enrollment** (a human completes the provider's own login flow):

```bash
# Codex — ChatGPT login via device code (enable "device code login" in ChatGPT security settings)
acp-runnerctl auth enroll codex personal-1                      # --runtime local (CLI on this machine)
acp-runnerctl auth enroll codex personal-1 --runtime docker     # inside the pinned runner image
acp-runnerctl auth enroll codex personal-1 --runtime kubectl    # temporary pod in acp-runner-system
acp-runnerctl auth enroll codex personal-1 --method browser     # localhost:1455 callback flow
acp-runnerctl auth enroll codex team-1 --method access-token    # ChatGPT Enterprise workspace token
acp-runnerctl auth enroll codex personal-1 --from-file ~/auth.json   # auth.json from `codex login` elsewhere

# Claude — Anthropic's documented long-lived token for CI/scripts
acp-runnerctl auth enroll claude max-1            # runs `claude setup-token`, then asks you to paste it (hidden)
claude setup-token | ... ; acp-runnerctl auth enroll claude max-1 --token-stdin

acp-runnerctl auth list                           # NAME PROVIDER AUTH PLAN FINGERPRINT LEASES STATUS
acp-runnerctl auth inspect personal-1             # derived facts only (auth mode, plan, masked email,
                                                  # expiry, fingerprints); never token values
acp-runnerctl auth disable|enable personal-1      # journal status (needs DATABASE_URL)
```

Enrollment isolates the CLI in a temporary `HOME`/`CODEX_HOME`/`CLAUDE_CONFIG_DIR`,
verifies the result with `codex login status` / `claude auth status --json` (no model
request), refuses API keys (`OPENAI_API_KEY` in `auth.json`, `auth_mode: apikey`,
`sk-ant-api…` tokens), and never passes secrets in process arguments. The Claude token is
read with a hidden prompt; Claude Code prints it to the terminal by design (it "does not
save the token anywhere").

**Storage.** `--store k8s` (default): one Secret per profile, `acp-cred-<profile>` in
`acp-runner-system`, with non-secret metadata in annotations. Agent pods never mount these;
the controller copies only the leased profile's whitelisted keys into an immutable
per-attempt Secret mounted read-only. **Kubernetes Secrets are only base64-encoded unless
the cluster has encryption at rest configured** (`EncryptionConfiguration`/KMS) — enable it,
restrict `get secrets` in `acp-runner-system`, and audit access. The store is a trait
(`CredentialStore`); a Vault/External-Secrets implementation needs only `list/load/save/
update_file/delete`. `--store file` is for development (`dev-run`).

**Codex keep-alive.** OpenAI documents that Codex treats a session as stale after about 8
days without refresh. Profiles that are used at least weekly stay fresh through normal runs
(refresh happens inside runs and is written back). Otherwise re-enroll when `auth inspect`
shows an old `lastRefresh` or runs fail with `AuthEnrollmentRequired`.

## 8b. Trust model: who may use credentials (V2)

Three parties are mutually untrusting; the controller enforces all of it:

| Who | Trusted to | NOT trusted to |
|---|---|---|
| profile admin (enroller) | choose which namespaces × runner classes may lease a profile (`auth allow`) | run workloads; their login is never exposed beyond the lease |
| runner-class author | pick image, command, env, service account | touch any credential: a class only *names* profiles, and the lease is granted solely on the profile's admin-written policy |
| run author (ACPRun) | name classes in their own namespace | elevate: naming an admin's class or profile without a grant fails the run (`CredentialUnavailable`), and a credentialed class additionally requires an operator-allowlisted digest-pinned image |

Enforcement points (defense in depth, default-deny everywhere):

1. **Lease issuance** (`Journal::start_attempt`): the profile must explicitly grant
   the attempt's namespace **and** runner class, otherwise `CredentialUnusable`.
   Empty grants deny — including every profile enrolled before V2, which stops
   working until an admin grants it (breaking change, intended).
2. **Admission** (engine reconcile, before any lease): a credentialed class runs
   only on an image from `ACP_RUNNER_ALLOWED_IMAGES` (exact `repo@sha256:<hex>`
   match) and a service account from `ACP_RUNNER_ALLOWED_SERVICE_ACCOUNTS`
   (default `acp-runner-agent`), otherwise `Unsupported`.
3. **Write-back** (V1): only the provider-verified account lands in the store.

```bash
acp-runnerctl auth enroll codex team-1 --method access-token \
  --allow-namespace team-a --allow-class codex-prod
acp-runnerctl auth allow team-1 --store k8s \
  --allow-namespace team-a --allow-namespace team-b \
  --allow-class codex-prod
```

Breaking changes (V2): profiles need explicit grants; credentialed classes need
allowlisted digest-pinned images (`ACP_RUNNER_ALLOWED_IMAGES`) instead of tags.

## 9. Authentication findings (verified 2026-09-26)

Primary sources, re-checked when this repository was written; re-verify before relying on
them — provider policies changed repeatedly during 2026.

**OpenAI Codex** ([Authentication](https://developers.openai.com/codex/auth),
[Maintain Codex account auth in CI/CD](https://learn.chatgpt.com/docs/auth/ci-cd-auth)):
* ChatGPT sign-in caches credentials in `~/.codex/auth.json` (under `CODEX_HOME`) or the OS
  keyring; `cli_auth_credentials_store = "file" | "keyring" | "auto" | "ephemeral"`.
* Headless options: `codex login --device-auth` (device code, must be enabled in ChatGPT
  settings), copying `auth.json` from a machine with a browser, or SSH port forwarding of
  the localhost:1455 callback.
* CI/CD with ChatGPT-managed auth is documented for *trusted private infrastructure*:
  restore `auth.json`, run Codex, persist the **refreshed** file; "use one `auth.json` per
  runner or per serialized workflow stream"; "do not share the same file across concurrent
  jobs or multiple machines". acp-runner implements exactly this (exclusive lease +
  validated write-back). OpenAI also recommends API keys for programmatic CI workflows and
  warns against untrusted/public environments — acp-runner deliberately uses the ChatGPT
  login path per the task constraints; operate it only for private repositories on trusted
  infrastructure you control.
* Workspace **access tokens** (`printenv CODEX_ACCESS_TOKEN | codex login --with-access-token`)
  exist for trusted non-interactive workflows in Enterprise workspaces
  (`--method access-token`).
* Verified in codex-rs 0.157.1 source: `auth.json` fields (`auth_mode`, `OPENAI_API_KEY`,
  `tokens{id_token,access_token,refresh_token,account_id}`, `last_refresh`, …), auth-mode
  names, `codex login status` messages/exit codes, `CODEX_HOME` must exist.

**codex-acp** (`@agentclientprotocol/codex-acp` 1.13.1, stdio ACP server that starts the
Codex app server): supports ChatGPT, API-key and gateway auth methods; `NO_BROWSER=1` hides
browser login; `CODEX_PATH` selects the Codex binary; `INITIAL_AGENT_MODE` selects
`read-only|agent|agent-full-access`. Observed: ACP `protocolVersion: 1`; without login,
`session/new` returns `-32000 Authentication required`. acp-runner never calls ACP
`authenticate`.

**Anthropic Claude Code** ([Authentication](https://code.claude.com/docs/en/authentication),
[Legal and compliance](https://code.claude.com/docs/en/legal-and-compliance),
[Run Claude Code programmatically](https://code.claude.com/docs/en/headless),
[Agent SDK with your Claude plan](https://support.claude.com/en/articles/15036540-use-the-claude-agent-sdk-with-your-claude-plan)):
* `claude setup-token` "generate[s] a one-year OAuth token … for CI pipelines, scripts, or
  other environments where interactive browser login isn't available", requires a Pro, Max,
  Team or Enterprise plan, "can only make model requests", and is passed as
  `CLAUDE_CODE_OAUTH_TOKEN`. Credentials from `/login` live in `~/.claude/.credentials.json`
  on Linux; acp-runner does **not** relocate that file (not documented as portable).
* Precedence: cloud-provider env > `ANTHROPIC_AUTH_TOKEN` > `ANTHROPIC_API_KEY` >
  `apiKeyHelper` > `CLAUDE_CODE_OAUTH_TOKEN` > profiles > `/login`. acp-runner therefore
  scrubs every higher-precedence variable, and aborts an attempt when the stream-json
  `system/init` message reports `apiKeySource` other than `none`.
* `--bare` ignores `CLAUDE_CODE_OAUTH_TOKEN` (API key only) → never used.
* Legal & compliance: OAuth is for subscription purchasers and "ordinary use of Claude Code";
  third-party developers may not offer Claude.ai login in their products or route requests
  through Free/Pro/Max credentials on behalf of *their users*, and must not "collect, store,
  or intermediate Claude.ai credentials"; it does not prevent "an end user from signing in to
  the unmodified Claude Code binary with their own Claude subscription, including where a
  platform hosts Claude Code". acp-runner runs the **unmodified** binary with the account
  owner's own `setup-token` on the owner's infrastructure. Do **not** operate it as a service
  for other people's Claude accounts; advertised Pro/Max limits "assume ordinary, individual
  usage".
* Billing: a change that would have moved Agent SDK, `claude -p` and third-party-app usage
  to a separate monthly credit (announced for 2026-06-15) is **paused**; per the help center
  all of these "still draw from your subscription's usage limits". Because `claude -p` and the
  Agent SDK are in the same bucket, the driver choice below is about fidelity and fewer
  moving parts, not cost — re-check this page before relying on the cost model.
* Why not `@agentclientprotocol/claude-agent-acp`: it is built on the Claude Agent SDK. The
  claude driver runs the native CLI's documented non-interactive interface (`-p
  --input-format/--output-format stream-json`) and normalizes events itself.

**ACP** ([agentclientprotocol.com](https://agentclientprotocol.com)): the client implements
v1 (`agent-client-protocol-schema` 1.9.1 method names; `sessionUpdate` variants; permission
outcomes); ACP v2 exists in the SDK but the adapters used here speak v1. Version negotiation:
send 1, accept only 1, otherwise fail with `Unsupported`.

## 10. Live smoke tests (opt-in)

They spend a small amount of real subscription usage. Success criteria never look at prose:
the run succeeds, the patch parses, only `add.sh` changed, the patch applies to the base
revision and `sh test.sh` prints PASS.

On the cluster:

```bash
acp-runnerctl auth enroll codex personal-1      # §8
scripts/live-smoke.sh codex                     # applies runnerclass-codex.yaml + acprun-codex-smoke.yaml

acp-runnerctl auth enroll claude max-1
scripts/live-smoke.sh claude
```

On the host (driver contract suite against the pinned CLIs; no cluster):

```bash
ACP_COMPAT_CODEX_AUTH_JSON=/secure/path/auth.json   scripts/compat.sh --targets codex
ACP_COMPAT_CLAUDE_TOKEN_FILE=/secure/path/token     scripts/compat.sh --targets claude
```

The live compat targets reuse the same eight contract tests (probe, auth detection, session,
prompt, output, cancellation, exit, mutation, patch). Keep the credential files outside the
repository; a used Codex `auth.json` is refreshed in a temp copy and not written back by the
host suite (re-export it from the store afterwards if you want to keep the refresh).

## 11. Runner image, version pinning and upgrades

`images/runner/Dockerfile` builds one generic image: runnerd, fake-acp-agent, git,
CA certificates, tini (PID 1, zombie reaping), and the CLIs from
`images/runner/package.json` + `package-lock.json` (`npm ci`, integrity-checked, exact
versions only — enforced by a test). The fixture repository is baked in as a bare repo at
`file:///opt/acp-runner/fixtures/buggy-repo.git` with the deterministic commit
`dab04cf7a90ba80a2e188cd4864c71abf7b39a74`. Auto-update is disabled for Claude
(`DISABLE_AUTOUPDATER`, `DISABLE_UPDATES`) and Codex (`check_for_update_on_startup = false`),
and the root filesystem is read-only at runtime anyway. Pin base images by digest with
`scripts/pin-base-images.sh`.

Current pins (see `drivers.lock.yaml` for status):

| driver | CLI | adapter | protocol |
|---|---|---|---|
| fake | fake-acp-agent (workspace) | – | ACP v1 |
| codex | `@openai/codex` 0.156.1 | `@agentclientprotocol/codex-acp` 1.13.1 | ACP v1 |
| claude | `@anthropic-ai/claude-code` 2.1.274 (npm `stable`) | – (native) | stream-json |

**Upgrade / regression flow** (touches only `images/runner/` and `drivers.lock.yaml`
unless the driver contract changed):

```bash
scripts/upgrade-cli.sh codex 0.157.1            # pin, regenerate lock, mark candidate, run suite
scripts/upgrade-cli.sh claude 2.1.283 --image   # + build candidate image, in-image contract smoke
scripts/compat.sh --targets fake-acp,fake-claude,codex-noauth    # test current pins
scripts/build-images.sh --tag candidate-x && scripts/compat-image.sh acp-runner/runner:candidate-x fake-acp,codex-noauth
scripts/build-images.sh --push ghcr.io/you      # records the runner digest in drivers.lock.yaml
```

Roll out by pointing `ACPRunnerClass.spec.image` of one class at the candidate image (e.g.
`codex-canary`) and using it as the primary class for a subset of runs; the rest keep the
previous image. Each attempt journals the detected CLI/adapter versions (`AgentStarted`,
`attempts.driver_version`, artifact metadata).

## 12. Kubernetes model

**CRDs** (`acp-runner.dev/v1alpha1`, generated by `crdgen`):

`ACPRunnerClass.spec`: `driver`, `driverConfig` (opaque), `image`, `imagePullPolicy`,
`runtimeClassName`, `resources`, `credentials{provider, profiles[], fileTargets{}}`,
`workspace{medium, sizeLimit, tmpSizeLimit, homeSizeLimit, maxPatchBytes, allowedPaths[]}`,
`timeouts{hardSeconds, noProgressSeconds, graceSeconds, heartbeatSeconds, startupSeconds}`,
`permissions{mode: AllowAll|DenyAll}`, `egress{httpsProxy, noProxy}`, `env[]`,
`runAsUser`, `serviceAccountName`.

`ACPRun.spec`: `taskId`, `runnerClassName`, `fallbackRunnerClassNames[]`,
`repository{url, revision, sparsePaths[], depth}`, `prompt{text}`,
`output{type: Patch|None, requireChanges, maxPatchBytes}`,
`retry{maxAttemptsPerRunner, maxTotalAttempts}`, `timeouts{…}`,
`resume{applyPreviousPatch, includeTranscript, maxTranscriptMessages}`, `cancel`.

`ACPRun.status` (operational only — no transcripts): `phase`, `runId`, `currentAttempt`,
`attemptId`, `attemptPhase`, `runnerClass`, `driver`, `credentialProfile`,
`sandboxRef{kind,namespace,name}`, `startedAt`, `finishedAt`, `lastHeartbeatTime`,
`lastProgressTime`, `failureReason{code,message}`, `artifactRef{id,kind,sha256,sizeBytes,
changedPaths,baseRevision,storage}`, `message`.

The run spec (including resolved runner classes) is **snapshotted** when the run is first
seen; editing a class does not affect in-flight runs. Deleting an `ACPRun` runs the
finalizer: attempts are cancelled, sandboxes terminated, leases released; the journal is kept.

**Sandbox backends** (`ACP_RUNNER_BACKEND`):

* `pod` (default): one Pod + one immutable per-attempt Secret, owner-referenced to the
  ACPRun (same namespace) so garbage collection is a second safety net.
* `agent-sandbox`: one `agents.x-k8s.io/v1beta1` `Sandbox` per attempt using
  [kubernetes-sigs/agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox) v1.0.x
  (install `sandbox-with-extensions.yaml` from its release). The same hardened pod template
  is embedded; `service: false`, `shutdownTime` = deadline backstop, `shutdownPolicy:
  Delete`; completion is read from the `Finished` condition. *Decision:* Agent Sandbox is
  beta and designed around long-lived, stateful sandboxes with warm pools; our attempts are
  run-to-completion and need per-attempt credential Secrets at creation time, so
  `SandboxTemplate`/`SandboxClaim`/`SandboxWarmPool` would not remove code here yet. The
  plain Pod backend stays default; the Sandbox backend is available behind the same trait
  (objects validated against the upstream v1beta1 CRD; its controller was not run by the
  author). A future warm-pool mode would have runnerd pull its attempt assignment after a
  claim.

**RBAC** (`deploy/controller/rbac.yaml`): the controller has a Role in `acp-agents`
(ACPRuns/status/finalizers, ACPRunnerClasses, pods, secrets get/create/delete, sandboxes)
and a Role for Secrets in `acp-runner-system` (credential store). The agent service account
`acp-runner-agent` has no bindings and no token.

**Controller replicas.** Safe to run more than one: every reconcile holds a
transaction-scoped PostgreSQL advisory lock on the run; attempts carry a supervision lease
(`lease_owner`, `lease_expires_at`, 45 s) — an instance that finds another live owner backs
off; an expired lease is taken over (journaled as `Progress/supervision_takeover`).

## 13. Sandbox and filesystem security

Every attempt pod (`crates/acp-runner-k8s/src/pod.rs`, enforced by tests):

* `automountServiceAccountToken: false`, dedicated SA without RBAC, `enableServiceLinks: false`
* `runAsNonRoot`, uid/gid 10001, `fsGroup`, `seccompProfile: RuntimeDefault`
* container: `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`,
  `capabilities.drop: [ALL]`, `privileged: false`
* writable mounts only: `/workspace` (memory emptyDir, the git worktree), `/tmp` (memory,
  bounded), `/home/agent` (memory, synthetic HOME); credentials at
  `/var/run/acp-runner/attempt` (Secret, read-only, `0440`)
* no hostPath, no container-runtime socket, no PVCs, no host namespaces
* `runtimeClassName` when configured (e.g. `gvisor`; `deploy/gvisor/runtimeclass.yaml`)
* `activeDeadlineSeconds` = hard + startup + 2·grace + 60 (kubelet backstop)
* namespace labelled Pod Security `restricted`

Inside, runnerd separates: (1) credential material (read-only mount, copied once into
HOME with `O_NOFOLLOW|O_CREAT|O_EXCL`), (2) provider config (driver-generated, e.g.
`$HOME/.codex/config.toml`), (3) ephemeral caches/state (`$HOME/.cache`, `.local`, …),
(4) the project workspace. Persistent credential state is never writable by a run: the CLI
works on a copy and only the controller's validated write-back reaches the store.
runnerd self-checks the posture at start (uid, SA token, runtime sockets, rootfs, CapEff,
NoNewPrivs, seccomp, tmpfs) and, with `ACP_RUNNER_STRICT_POSTURE=true` (set by the Kubernetes
backends), fails the attempt before any credential is placed if an invariant is violated.

Workspace: `git init` + `git fetch --depth=N origin <exact SHA>` (+ `--filter=blob:none`
and non-cone sparse checkout when `sparsePaths` are given), detached checkout, SHA verified.
All git commands run with system/global config disabled, hooks disabled, fsmonitor off,
`protocol.ext` disabled, no external diff/textconv, no prompts. Because the agent controls
`.git/config` (e.g. `core.fsmonitor`, filter drivers — tested), runnerd restores the pristine
config it kept **in memory** before collecting the patch. The patch is
`git diff --cached --binary --full-index <base>` over a copied index (tracked + untracked,
`.gitignore` respected, committed changes included), with size cap, symlink-escape
rejection, allowed-path prefixes, and `.git`/`..` path checks. Files written outside the
repository never enter the patch.

Accepted residual risks (documented, by design): the agent runs as the same uid as runnerd
inside the sandbox, so it can read the attempt token and the leased credential (it needs the
credential anyway). The token only allows appending events/heartbeats/artifacts for *its own
active attempt* and proposing a credential write-back that must pass validation. Everything a
runner submits is treated as untrusted (kinds restricted, payloads re-redacted, sizes and
hashes verified).

## 14. Network model and its actual guarantees

`deploy/agents/networkpolicy.yaml` (needs a NetworkPolicy-enforcing CNI):

* no ingress to agent pods;
* egress only to cluster DNS, the controller ingest port, and TCP 443/80 to addresses
  **outside** RFC1918, CGNAT (100.64/10), link-local (incl. 169.254.169.254 metadata),
  loopback (IPv4 and IPv6 equivalents).

Guaranteed: agents cannot reach other pods/services, private node IPs, cloud metadata, or an
API server on a private address. **Not** guaranteed: NetworkPolicy cannot filter by
hostname or URL — agents can reach any public HTTPS host. If your API server has a public
endpoint, add its address to `except` (the agent still has no token or RBAC). For domain
allowlists use the optional egress proxy hook: `ACPRunnerClass.spec.egress.httpsProxy` makes
runnerd export `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` to the agent and to its own git fetch,
and `deploy/egress-proxy/` contains a proxy-only NetworkPolicy plus an example Squid
allowlist (verify the hosts your pinned CLI versions use via the proxy's access log).

## 15. Runtime internals

**Events** (append-only `session_events`, trigger rejects UPDATE/DELETE/TRUNCATE;
idempotent per `(attempt_id, seq)`): `RunCreated`, `AttemptStarted`, `AgentStarted`,
`SessionStarted`, `InputSent`, `AgentOutput` (coalesced chunks, `message|thought`),
`ToolCall`, `ToolResult`, `PermissionRequest` (decision), `Progress` (plan, usage, rate
limits, posture, workspace, probe, protocol warnings, …), `ArtifactCreated`, `Heartbeat`
(journaled ≤ 1/min; every heartbeat updates `attempts.last_heartbeat_at`), `AttemptFailed`,
`AttemptTimedOut`, `AttemptCompleted`, `RunCompleted`, `RunFailed`. `data` is normalized and
redacted; `raw` optionally preserves the provider message (redacted, ≤ 32 KiB). Redaction
combines literal secrets known to runnerd (credential values, token) with patterns
(Anthropic/OpenAI keys, JWTs, bearer headers, GitHub tokens) and sensitive JSON keys, and is
applied again in the ingest API.

**Tables:** `runs`, `attempts`, `session_events`, `artifacts`, `credential_profiles`,
`credential_leases` (`crates/acp-runner-journal/migrations/0001_init.sql`).

**Heartbeat / hang detection:**

| condition | detected by | result |
|---|---|---|
| running normally | fresh heartbeats + progress events | – |
| no progress | runnerd watchdog (`noProgressSeconds`); engine backstop (+2·grace+30 s) | `session/cancel` / SIGINT → grace → SIGTERM (process group) → SIGKILL → `AttemptTimedOut(NoProgressTimeout)` |
| hard timeout | runnerd; engine backstop; kubelet `activeDeadlineSeconds` | same escalation → `HardTimeout` |
| agent process crashed | runnerd sees exit without a finished turn | `ProcessCrashed{exit_code, signal, stderr tail (redacted)}` |
| runnerd crashed | sandbox exited without terminal report | `ProcessCrashed` (runnerd) / `SandboxFailed` (image pull, OOM, …) |
| runnerd hung / partitioned | heartbeat older than 3·interval+15 s | `HeartbeatLost` |
| sandbox disappeared | backend reports missing | `SandboxLost` |
| never started | no heartbeat within `startupSeconds` | `StartTimeout` |

Agent processes run in their own process group with `PR_SET_PDEATHSIG=SIGKILL`, so they
never outlive runnerd.

**Retry / fallback:** classes `[primary, fallbacks…]`, `maxAttemptsPerRunner` attempts each,
optional `maxTotalAttempts`. Failure dispositions: `RetrySame` (crashes, timeouts, protocol
errors, no changes, …), `SkipToFallback` (`AuthEnrollmentRequired`, `AuthPolicyViolation`,
`Unsupported`, `CredentialUnavailable`), `Fatal` (cancellation). Example
(`deploy/examples/acprun-claude-then-codex.yaml`): claude → claude → codex.

**Resume capsule:** every retry/fallback starts a **new provider session**; provider-internal
state is never assumed portable. The engine renders a provider-neutral capsule from canonical
state into the prompt: original task, repository and resolved base revision, previous attempts
(class, driver, outcome, failure, last message, tool-call count), recent normalized agent
messages and tool errors, latest diagnostics, and the latest (partial) patch — either as text
or, with `resume.applyPreviousPatch`, applied to the fresh workspace before the agent starts.

**Artifacts:** base revision, binary git patch, changed paths (status, binary, symlink),
SHA-256 (verified on upload and read), driver + detected version, attempt id. Stored inline
in PostgreSQL up to `ACP_RUNNER_ARTIFACT_INLINE_LIMIT` (8 MiB), optionally in a `BlobStore`
beyond that (filesystem implementation; S3 fits the same trait), otherwise rejected
(`ArtifactTooLarge`). Failed attempts upload their non-empty patch as `partial_patch`.
acp-runner never applies a patch to an authoritative repository.

## 16. Observability

JSON logs (`tracing`) with `run_id`, `attempt_id`, `driver` fields; never credential values.
Prometheus at `:8080/metrics` (`/healthz`, `/readyz`):

`acp_runner_runs_total{result}`, `acp_runner_attempts_total{driver,runner_class}`,
`acp_runner_attempt_duration_seconds{driver,phase}`,
`acp_runner_attempt_failures_total{driver,reason}`, `acp_runner_active_attempts{driver}`,
`acp_runner_timeouts_total{driver,kind}`, `acp_runner_fallbacks_total{from_driver,to_driver}`,
`acp_runner_credential_writebacks_total{result}`.

Run/attempt ids are deliberately not metric labels (cardinality); use the journal
(`acp-runnerctl run events`) and logs for per-run detail.

## 17. Drivers and how to add one

```rust
trait AgentDriver {                    // crates/acp-runner-drivers/src/lib.rs
    fn name(&self) -> &'static str;
    fn protocol(&self) -> &'static str;
    async fn probe(&self, ctx) -> Result<ProbeReport>;     // executable, version, auth state (no secrets, no model call)
    async fn prepare(&self, ctx) -> Result<()>;            // driver config inside the synthetic HOME
    async fn spawn(&self, ctx) -> Result<Box<dyn AgentProcess>>;
    async fn collect_artifact(&self, ws, opts) -> Result<PatchArtifact>;   // default: git patch
}
trait AgentProcess {
    async fn initialize_session(&mut self) -> Result<SessionInfo>;
    async fn send_prompt(&mut self, text: &str) -> Result<()>;
    async fn next_event(&mut self) -> Option<DriverEvent>; // stream_events
    async fn cancel(&mut self) -> Result<()>;              // graceful
    fn health(&self) -> ProcessHealth;
    async fn shutdown(&mut self, grace) -> ExitInfo;       // SIGTERM group -> grace -> SIGKILL
}
```

Driver configuration (`ACPRunnerClass.spec.driverConfig`):

* `fake`: `command`, `args`, `scenario`, `env`
* `acp` (V9, any stdio ACP CLI): `command` (required), `args`, `env`, `files`
  (`[{target, content, mode}]` placed in the HOME). Model and other settings are
  plain launch parameters (`env` or `files`), selectable per run via
  `ACPRun.spec.overrides` when the class sets `allowRunOverrides: true`.
* `codex`: `mode` (`agent-full-access` default | `agent` | `read-only`), `model`,
  `reasoningEffort`, `codexConfig{}` (→ `CODEX_CONFIG`), `extraConfigToml`,
  `adapterCommand` (`codex-acp`), `adapterArgs`, `codexCommand` (`codex`, passed as
  `CODEX_PATH` so the probed binary is the one used), `env`
* `claude`: `permissionMode` (`acceptEdits` default), `allowedTools[]`,
  `disallowedTools[]`, `model`, `settingSources` (`user`), `appendSystemPrompt`,
  `disableNonessentialTraffic` (true), `extraArgs[]` (`--bare` refused), `command`,
  `commandArgs`, `env`

Credential providers: `codex` (ChatGPT login, exclusive lease, validated
write-back), `claude` (setup-token, shared leases), `files` (V9: generic named
files from `--from-file` (+ `--select`), targets from the class `fileTargets`,
no refresh, no write-back).

To add a CLI: for an ACP-speaking CLI use `driver: acp` with a launch spec —
no code change — plus a `drivers.lock.yaml` conformance profile
(`bins/runnerd/tests/acp_conformance.rs`, `ACP_CONFORMANCE_LAUNCH` for live
runs). A non-ACP CLI still needs a new driver module: implement the traits
(an ACP-speaking CLI can reuse `acp_driver::AcpProcess`), register it in
`driver_for`, add its credential whitelist to
`acp-runner-core/src/credentials.rs` if it needs one, pin it in `images/runner/package.json`,
add a `drivers.lock.yaml` entry and a compat target. CRDs, engine, journal and controller do
not change (driver = name + opaque config).

## 18. Security test map

| requirement | test |
|---|---|
| path traversal | `core::paths::tests`, `core::spec::tests::rejects_traversal_in_sparse_paths`, `runnerd home::tests::traversal_and_symlink_targets_are_refused` |
| symlink escape | `workspace::tests::symlink_escape_is_rejected`, `runnerd security::symlink_escape_fails_the_attempt` |
| git config tampering | `workspace::tests::tampered_git_config_is_neutralized` |
| credential values never in logs/journal | `runnerd security::credential_values_never_reach_events_logs_or_artifacts`, `core::redact::tests`, `acp-runnerctl cli::codex_import_list_and_inspect_never_print_secrets` |
| env redaction / API-key env refused | `core::redact::tests::env_redaction`, `drivers::env::tests`, `runnerd security::forbidden_environment_is_refused`, `drivers::process::tests::environment_is_not_inherited` |
| SA token absent / credentials mounted only where intended | `k8s::pod::tests::pod_is_hardened`, `secret_holds_only_token_and_whitelisted_files`, kube e2e (submitted pod spec), `scripts/e2e-kind.sh` (live pod) |
| workspace ephemeral | pod volumes are memory emptyDirs only (`pod_is_hardened`); sandbox dirs removed (`engine e2e fake_run_succeeds…`) |
| unauthorized Secret access impossible | kube e2e step 5 (impersonated agent SA → 403), `scripts/e2e-kind.sh` (`kubectl auth can-i`) |
| subprocess cancellation | `drivers::process::tests::terminate_escalates_to_sigkill_for_the_whole_group`, compat `c04`, `c07` |
| stale attempt lease recovery | `journal::tests::supervision_lease_takeover_of_stale_controller`, `engine e2e stale_controller_is_taken_over_by_another_instance`, expired credential leases in `credential_leases_are_exclusive_expire_and_respect_status` |
| patch artifact size limit | `workspace::tests::size_limit_enforced`, `runnerd security::patch_size_limit_is_enforced`, `engine e2e oversized_artifact_is_rejected_by_ingest`, `journal::tests::artifact_store_inline_external_and_limits` |
| API keys refused | `core::credentials::tests`, `drivers::claude::tests::api_key_source_is_a_policy_violation`, `runnerd security::api_key_mode_is_a_policy_violation`, `acp-runnerctl cli::api_keys_are_refused_for_both_providers` |
| ingest authentication | `engine e2e ingest_rejects_bad_tokens_and_forbidden_event_kinds` |
| write-back validation | `core::credentials::tests::writeback_requires_same_account`, engine/kube e2e write-back |
| credential usage grants (V2) | `journal::tests::profile_policy_denies_by_default_and_grants_explicitly`, `engine e2e cross_namespace_class_reference_cannot_borrow_credentials` |
| credentialed image/SA admission (V2) | `core::spec::tests::credentialed_image_needs_digest_pin_and_allowlist`, `service_account_resolves_default_and_checks_allowlist`, `engine e2e credentialed_class_admission_rejects_unpinned_unknown_image_and_sa` |
| bootstrap never sees credentials (V4) | `runnerd home::base_then_place_defers_credentials_past_bootstrap`, `engine environment_provider::bootstrap_cannot_see_credentials_placed_after_it` |
| bootstrap background processes killed (V4) | `agentd reap::live_background_child_is_killed_and_reaped`, `engine environment_provider::bootstrap_background_process_fails_and_is_reaped` |
| bootstrap cwd without symlinks (V4) | `drivers::process::secure_cwd_enters_the_directory_without_following_links` |
| durable directive queue (V5) | `journal::tests::env_directives_queue_deliver_ack_and_redeliver`, `engine directives::directive_queued_on_a_delivered_on_b_with_ack`, `cancel_is_checked_before_the_queue`, `unacked_directive_is_redelivered` |
| targeted event reads (V5) | `journal::tests::targeted_progress_reads_replace_full_scans`, `engine directives::refresh_over_200k_events_stays_fast` (200k events, <50ms) |
| multi-replica ingest (V5) | `engine directives::directive_queued_on_a_delivered_on_b_with_ack` backs the `controller.rs` multi-replica claim |
| gitlink refused (V6) | `workspace::tests::nested_git_init_is_rejected_as_gitlink` (gitlink denied even with `allowSubmodules`) |
| `.gitmodules` opt-in (V6) | `workspace::tests::gitmodules_change_is_rejected_unless_allowed` |
| parallel collection (V6) | `workspace::tests::parallel_collects_are_identical` (per-call UUID index names) |
| staged modes visible (V6) | `workspace::tests::prepare_modify_collect_and_apply` (`ChangedPath.mode`) |
| JSON-leaf redaction (V8) | `core::redact::tests::refresh_token_without_prefix_is_redacted`, `json_files_contribute_leaves_not_the_whole_file` |
| gateway phase-before-nonce + overload (V8) | `runnerd gateway::ticket_survives_409_and_works_when_idle`, `hundred_hanging_handshakes_do_not_block_a_real_one` |
| gateway byte transparency (V8) | `runnerd gateway::websocket_frames_become_single_lines_byte_for_byte`, `invalid_utf8_on_raw_is_dropped_and_stream_resyncs` |
| `file://` opt-in (V8) | `core::spec::tests::file_urls_need_an_explicit_opt_in` (`ACP_RUNNER_ALLOW_FILE_REPOS`) |
| single patch overlay (V8) | `core::environment::tests::at_most_one_patch_artifact_overlay` |
| generic acp driver (V9) | `drivers::generic_acp_driver_requires_a_command`, `drivers::launch_files_land_in_home_without_following_links` |
| run overrides (V9) | `engine e2e run_overrides_without_opt_in_fail_before_any_sandbox` (A22), `run_overrides_cannot_redirect_home_or_proxy` (A23), `same_class_two_runs_with_different_models_via_overrides` (A21) |
| files provider (V9) | `core::credentials::tests::files_bundles_take_any_safe_filenames`, `runnerctl cli::files_enroll_stores_from_file_with_select`, `engine e2e files_profile_leases_and_lands_at_file_targets` |
| acp-conformance (V9) | `runnerd acp_conformance_*` (startup/session, cancel, permission, stdin-close, profile; A24) |
| no public controller egress (V2) | `controller deploy_policy::controller_has_no_public_egress_cidr`, `proxy_admits_the_controller`, `controller_routes_refresh_through_the_proxy_by_default` |

## 19. Findings, incompatibilities and limitations

Discovered while building/testing:

* **Racy git index** — an agent edit in the same second as checkout that keeps the file size
  (`-` → `+`) was invisible to `git add -A` on a *copied* index (the copy's fresh mtime
  defeats git's racy-entry check). Fixed by back-dating the copied index; regression test
  `same_second_same_size_edit_is_detected`.
* **Codex:** `CODEX_HOME` must exist before start; under `/tmp` Codex only warns and skips
  its helper PATH aliases (pod HOME is `/home/agent`). Codex's own Linux sandbox generally
  cannot work unprivileged in a container → default `mode: agent-full-access` with the pod
  as the boundary (not yet validated live).
* **Claude Code:** `--bare` ignores `CLAUDE_CODE_OAUTH_TOKEN`; `-p` without `--setting-sources
  user --strict-mcp-config` would run hooks/MCP servers from the untrusted repository;
  managed settings in `/etc/claude-code` can inject an `apiKeyHelper` (guarded by the
  `apiKeySource` check). Run as non-root with a writable HOME only — not yet validated live
  with a real subscription.
* **Zombies:** without an init process, killed agent grandchildren stay as zombies → tini is
  PID 1 in the runner image.
* **rustls** rejects X.509 v1 certificates (envtest script issues v3 certs); kube-rs honours
  `HTTPS_PROXY` and needs the `http-proxy` feature if a proxy is set for the controller.
* Memory-backed volumes count against the pod memory limit; size `resources.limits.memory`
  accordingly. The runner image is large (~1.2 GB) because it ships both CLIs.

Limitations / next steps:

* Private repositories: no git credential support yet. Planned design: an init container
  (`runnerd prepare`) that alone mounts the git credential, so the agent container never sees it.
* No UI, no budget accounting, no multi-agent orchestration, no PR creation (non-goals).
* Agent Sandbox warm pools/claims not used (see §12). OpenTelemetry not added.
* The official ACP Rust SDK could replace the small `acp-runner-acp` client behind the same
  driver trait once its 2.x API settles; we chose a tolerant reader that preserves raw payloads.
* Artifact external storage: filesystem implementation only (S3 behind `BlobStore` pending).

## 20. Definition-of-done map

| # | item | how |
|---|---|---|
| 1 | build Rust components | `cargo build --workspace` |
| 2 | start PostgreSQL | `scripts/dev-postgres.sh` / `docker compose up -d postgres` / in-cluster `deploy/postgres` |
| 3 | CRDs + controller into KIND | `scripts/kind-up.sh && scripts/build-images.sh --kind && scripts/install.sh` |
| 4 | fake driver without credentials | `deploy/examples/runnerclasses-fake.yaml` (installed by `install.sh`) |
| 5 | create an ACPRun | `kubectl apply -f deploy/examples/acprun-fake.yaml` |
| 6 | observe attempt lifecycle | `kubectl -n acp-agents get acpruns,pods -w`; `acp-runnerctl run get` |
| 7 | normalized journal events | `acp-runnerctl run events <run> [-f] [--raw]` |
| 8 | patch artifact | `status.artifactRef`; `acp-runnerctl run artifact <run> -o fix.patch` |
| 9 | crashed/hung driver | `acprun-retry.yaml` (crash), `acprun-hang.yaml` (hang), §7 table |
| 10 | retry | `acprun-retry.yaml` → `currentAttempt: 2` |
| 11 | fallback | `acprun-fallback.yaml` → `runnerClass: fake-fix`, `AttemptStarted.fallback=true` |
| 12 | real runner image | `scripts/build-images.sh` |
| 13 | enroll Codex subscription login | `acp-runnerctl auth enroll codex personal-1` (§8) |
| 14 | Codex live smoke, no API key | `scripts/live-smoke.sh codex` |
| 15 | Claude subscription auth | `acp-runnerctl auth enroll claude max-1` via `claude setup-token` (§8, §9 for the policy basis) |
| 16 | Claude live smoke | `scripts/live-smoke.sh claude` |
| 17 | update a pinned CLI + regression suite | `scripts/upgrade-cli.sh codex 0.157.1 [--image]` |
