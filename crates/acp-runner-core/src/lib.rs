//! Provider-neutral domain model for acp-runner.
//!
//! This crate deliberately has no I/O. It defines:
//!
//! * the resolved run/runner-class specifications the engine works with ([`spec`]),
//! * the per-attempt document handed to `runnerd` inside the sandbox ([`attempt_spec`]),
//! * the durable agent-execution-environment primitive ([`environment`]),
//! * explicit state machines for runs and attempts ([`state`]),
//! * failure classification and the retry/fallback planner ([`failure`], [`plan`]),
//! * the append-only event model ([`events`]),
//! * the provider-neutral resume capsule used for retries and fallbacks ([`capsule`]),
//! * provider credential whitelists and bundle validation ([`credentials`]),
//! * secret redaction ([`redact`]) and path safety helpers ([`paths`]),
//! * signed environment connection tickets ([`ticket`]).
//!
//! Nothing in here knows how a particular CLI is installed or started; that lives in
//! `acp-runner-drivers`.

pub mod attempt_spec;
pub mod bundle;
pub mod capsule;
pub mod credentials;
pub mod environment;
pub mod events;
pub mod failure;
pub mod harness;
pub mod paths;
pub mod plan;
pub mod redact;
pub mod spec;
pub mod state;
pub mod ticket;

pub use attempt_spec::AttemptSpec;
pub use capsule::ResumeCapsule;
pub use environment::{EnvironmentPhase, EnvironmentSpec, HarnessSpec};
pub use events::{EventEnvelope, EventKind, EventSource};
pub use failure::{FailureReason, RetryDisposition};
pub use state::{AttemptPhase, RunPhase};

/// Version of the runner <-> controller wire contract (ingest API + AttemptSpec).
/// Bump when a breaking change is made so old runner images fail loudly.
///
/// * v1: single-container runnerd.
/// * v2: runnerd/agentd split (`source = agent`, heartbeat directives, egress mode).
/// * v3: environment dataplane = raw ACP behind signed connection tickets; trusted/untrusted
///   bootstrap plan (overlays, bundles, workdir, harness artifact) in the AttemptSpec.
pub const WIRE_VERSION: u32 = 3;
