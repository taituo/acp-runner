-- acp-runner journal schema v1
-- Runs are stable; attempts are disposable; session_events is append-only.

CREATE TABLE runs (
    id                  uuid PRIMARY KEY,
    k8s_namespace       text        NOT NULL,
    k8s_name            text        NOT NULL,
    k8s_uid             text        NOT NULL UNIQUE,
    task_id             text        NOT NULL,
    spec                jsonb       NOT NULL,          -- resolved RunSpec snapshot (no secrets)
    phase               text        NOT NULL,
    current_attempt_id  uuid        NULL,
    attempt_count       integer     NOT NULL DEFAULT 0,
    failure_reason      jsonb       NULL,
    artifact_id         uuid        NULL,
    waiting_reason      text        NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    started_at          timestamptz NULL,
    finished_at         timestamptz NULL,
    updated_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX runs_phase_idx ON runs (phase);
CREATE INDEX runs_task_idx ON runs (task_id);

CREATE TABLE attempts (
    id                  uuid PRIMARY KEY,
    run_id              uuid        NOT NULL REFERENCES runs (id),
    ordinal             integer     NOT NULL,
    class_index         integer     NOT NULL,
    class_attempt       integer     NOT NULL,
    runner_class        text        NOT NULL,
    driver              text        NOT NULL,
    phase               text        NOT NULL,
    spec                jsonb       NOT NULL,          -- AttemptSpec (no secrets)
    sandbox_ref         jsonb       NULL,              -- {backend, namespace, name}
    ingest_token_hash   text        NULL,              -- sha256(hex) of the bearer token
    credential_profile  text        NULL,
    lease_owner         text        NULL,              -- controller instance supervising the attempt
    lease_expires_at    timestamptz NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    sandbox_created_at  timestamptz NULL,
    sandbox_released_at timestamptz NULL,              -- sandbox terminated/cleaned up by the engine
    started_at          timestamptz NULL,              -- agent process started (runnerd report)
    last_heartbeat_at   timestamptz NULL,
    last_progress_at    timestamptz NULL,
    finished_at         timestamptz NULL,
    failure_reason      jsonb       NULL,
    outcome             jsonb       NULL,              -- stop reason, summary (redacted)
    driver_version      text        NULL,
    base_revision       text        NULL,
    artifact_id         uuid        NULL,
    UNIQUE (run_id, ordinal)
);
CREATE INDEX attempts_run_idx ON attempts (run_id, ordinal);
CREATE INDEX attempts_active_idx ON attempts (phase) WHERE phase IN ('Pending', 'Starting', 'Running');
CREATE UNIQUE INDEX attempts_token_idx ON attempts (ingest_token_hash) WHERE ingest_token_hash IS NOT NULL;

CREATE TABLE session_events (
    id                  bigserial PRIMARY KEY,
    run_id              uuid        NOT NULL REFERENCES runs (id),
    attempt_id          uuid        NULL REFERENCES attempts (id),
    seq                 bigint      NULL,              -- runnerd sequence number (idempotent re-delivery)
    ts                  timestamptz NOT NULL,
    recorded_at         timestamptz NOT NULL DEFAULT now(),
    kind                text        NOT NULL,
    source              text        NOT NULL,
    data                jsonb       NOT NULL,
    raw                 jsonb       NULL
);
CREATE UNIQUE INDEX session_events_attempt_seq ON session_events (attempt_id, seq) WHERE seq IS NOT NULL;
CREATE INDEX session_events_run_idx ON session_events (run_id, id);
CREATE INDEX session_events_attempt_kind_idx ON session_events (attempt_id, kind);

CREATE FUNCTION acp_runner_forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'session_events is append-only';
END;
$$;
CREATE TRIGGER session_events_append_only
    BEFORE UPDATE OR DELETE ON session_events
    FOR EACH ROW EXECUTE FUNCTION acp_runner_forbid_mutation();
CREATE TRIGGER session_events_no_truncate
    BEFORE TRUNCATE ON session_events
    FOR EACH STATEMENT EXECUTE FUNCTION acp_runner_forbid_mutation();

CREATE TABLE artifacts (
    id                  uuid PRIMARY KEY,
    run_id              uuid        NOT NULL REFERENCES runs (id),
    attempt_id          uuid        NOT NULL REFERENCES attempts (id),
    kind                text        NOT NULL,          -- patch | partial_patch
    base_revision       text        NOT NULL,
    sha256              text        NOT NULL,
    size_bytes          bigint      NOT NULL,
    changed_paths       jsonb       NOT NULL,
    driver              text        NOT NULL,
    driver_version      text        NULL,
    storage             text        NOT NULL,          -- postgres | external
    content             bytea       NULL,
    external_uri        text        NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    CHECK ((storage = 'postgres' AND content IS NOT NULL) OR (storage <> 'postgres' AND external_uri IS NOT NULL))
);
CREATE INDEX artifacts_run_idx ON artifacts (run_id, created_at);

CREATE TABLE credential_profiles (
    name                    text PRIMARY KEY,
    provider                text        NOT NULL,
    store                   text        NOT NULL,      -- e.g. k8s-secret:acp-runner-system/acp-cred-max-1
    status                  text        NOT NULL DEFAULT 'active',   -- active | disabled | needs_reauth
    max_concurrent_leases   integer     NOT NULL DEFAULT 1 CHECK (max_concurrent_leases >= 1),
    metadata                jsonb       NOT NULL DEFAULT '{}'::jsonb, -- non-secret CredentialMetadata
    material_fingerprint    text        NULL,
    generation              bigint      NOT NULL DEFAULT 0,
    last_error              text        NULL,
    last_used_at            timestamptz NULL,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE credential_leases (
    id                  uuid PRIMARY KEY,
    profile_name        text        NOT NULL REFERENCES credential_profiles (name),
    attempt_id          uuid        NOT NULL UNIQUE REFERENCES attempts (id),
    holder              text        NOT NULL,
    acquired_at         timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,
    released_at         timestamptz NULL
);
CREATE INDEX credential_leases_active_idx ON credential_leases (profile_name) WHERE released_at IS NULL;
