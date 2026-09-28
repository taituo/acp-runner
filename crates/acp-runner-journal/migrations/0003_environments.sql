-- acp-runner journal schema v3: durable AgentEnvironment handles.
--
-- An environment is backed by one long-lived attempt (the execution unit reused unchanged);
-- this table is the provider-facing handle the caller sees. It never stores the gateway token
-- (only its sha256), the provider (Claude/Codex) credential, or the ingest token.
CREATE TABLE environments (
    id                  uuid PRIMARY KEY,
    external_ref        text        NOT NULL,
    attempt_id          uuid        NOT NULL REFERENCES attempts (id),
    run_id              uuid        NOT NULL REFERENCES runs (id),
    harness             text        NOT NULL,
    phase               text        NOT NULL,               -- Creating|Idle|Busy|Finishing|Completed|Failed
    spec                jsonb       NOT NULL,               -- EnvironmentSpec (no secrets)
    gateway_token_sha256 text       NOT NULL,               -- sha256(hex) of the env-scoped token
    connection_ref      jsonb       NULL,                   -- {gateway: "host:port"} (no secret)
    base_revision       text        NULL,
    final_artifact_id   uuid        NULL,
    failure_reason      jsonb       NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    finished_at         timestamptz NULL
);
CREATE INDEX environments_external_idx ON environments (external_ref);
CREATE INDEX environments_phase_idx ON environments (phase);
