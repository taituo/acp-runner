-- acp-runner journal schema v2: runnerd/agentd split.
--
-- * cancel_requested_at / cancel_reason: the controller detected a condition (no agent
--   progress) and asks runnerd, through the heartbeat response, to cancel the agent. If the
--   attempt is still active after the grace window, the controller terminates the sandbox.
-- * session_events.source gains the value 'agent' (untrusted agentd claims); 'driver' is
--   kept for v1 rows. source is free text, so no DDL is needed for that.
ALTER TABLE attempts ADD COLUMN cancel_requested_at timestamptz NULL;
ALTER TABLE attempts ADD COLUMN cancel_reason jsonb NULL;
