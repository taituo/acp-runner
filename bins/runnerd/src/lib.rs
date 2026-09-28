//! runnerd — the trusted in-sandbox attempt supervisor.
//!
//! One runnerd process runs exactly one attempt:
//!
//! 1. fetch the [`AttemptSpec`](acp_runner_core::AttemptSpec) (ingest API, bearer token from
//!    the read-only per-attempt Secret mount that only the runnerd container has),
//! 2. check the sandbox posture (non-root, no service-account token, read-only rootfs, ...),
//! 3. bind the local agentd socket, prepare the disposable git workspace (exact revision,
//!    shallow, optional sparse) and snapshot the authoritative git directory privately,
//! 4. build the synthetic HOME and place whitelisted credential material as ephemeral copies,
//! 5. accept agentd (the untrusted executor in the agent container), send `Launch`,
//! 6. journal agentd's events as `source = agent`, heartbeat, enforce no-progress and hard
//!    timeouts (`Cancel` over IPC; the controller terminates the sandbox afterwards),
//! 7. compute the binary git patch itself, upload it, hand refreshed credential files back,
//! 8. report the terminal attempt event and exit.
//!
//! runnerd contains no provider driver code: the CLIs run only under agentd.

pub mod agent_link;
pub mod bootstrap;
pub mod environment;
pub mod gateway;
pub mod home;
pub mod posture;
pub mod sink;
pub mod supervisor;
pub mod tap;

pub use agent_link::AgentdLaunch;
pub use environment::{EnvironmentResult, run_environment};
pub use supervisor::{AgentView, AttemptResult, RunnerDirs, SupervisorOptions, run_attempt};
