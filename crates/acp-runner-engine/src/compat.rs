//! Compatibility wrapper: the classic one-shot `execute(repository, revision, prompt)` on top
//! of the general environment primitive — `create → connect → prompt → wait end_turn →
//! finish`. Existing one-shot callers keep working while the low-level primitive is general.
//!
//! This is deliberately conservative: one environment, no automatic fallback and no automatic
//! retry (that machinery stays in the run/attempt engine, which is unchanged).

use crate::environment::{EnvironmentProvider, EnvironmentView};
use acp_runner_client::{Transport, connect_session};
use acp_runner_core::environment::{EnvironmentSpec, HarnessSpec};
use acp_runner_core::spec::RepositoryInput;
use std::time::Duration;

/// A single-turn request expressed on the environment primitive.
#[derive(Debug, Clone)]
pub struct OneShot {
    pub external_ref: String,
    pub harness: HarnessSpec,
    pub repository: RepositoryInput,
    pub credential_profile: Option<String>,
    pub prompt: String,
}

/// Run one prompt in a fresh environment and finish it, returning the final view (with the
/// authoritative changeset artifact). `end_turn` returns the environment to Idle; `finish`
/// is what ends it — the wrapper makes that explicit boundary for the caller. The prompt
/// travels as plain ACP (`initialize`, `session/new`, `session/prompt`) through the gateway.
pub async fn execute(
    provider: &EnvironmentProvider,
    req: OneShot,
    timeout: Duration,
) -> anyhow::Result<EnvironmentView> {
    let cred = acp_runner_core::environment::CredentialSelection {
        profile: req.credential_profile.clone(),
        ..Default::default()
    };
    let mut spec = EnvironmentSpec::new(&req.external_ref, req.harness, Some(req.repository));
    spec.credentials = cred;
    let env = provider.create(spec).await?;
    let conn = provider.connect(env.id, timeout).await?;
    let turn = tokio::time::timeout(timeout, async {
        let (mut client, session) = connect_session(&conn.gateway, &conn.ticket, Transport::Raw).await?;
        let out = client.prompt(&session, &req.prompt).await?;
        client.close().await;
        anyhow::Ok(out)
    })
    .await;
    match turn {
        Ok(Ok(out)) => tracing::debug!(environment_id = %env.id, stop_reason = %out.stop_reason, "one-shot turn ended"),
        Ok(Err(e)) => tracing::warn!(environment_id = %env.id, error = %e, "one-shot turn failed; finishing anyway"),
        Err(_) => tracing::warn!(environment_id = %env.id, "one-shot turn timed out; finishing anyway"),
    }
    // Whatever the turn outcome, finish() is authoritative and collects the changeset.
    provider.finish(env.id, timeout).await
}
