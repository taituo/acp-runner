-- V5a: durable environment-directive queue (replaces the ingest in-memory
-- queue, so directives survive controller restarts and work across replicas).
-- V5a: per-attempt journaled-heartbeat cursor (replaces the ingest in-memory
-- hb_last map). V5b: expression index for latest-per-category progress reads.
--
-- Note: numbered 0009, not 0008 — 0008 is taken by the profile-policy
-- migration (the V5 plan predates it).

CREATE TABLE environment_directives (
    id          uuid        PRIMARY KEY,
    attempt_id  uuid        NOT NULL REFERENCES attempts (id),
    directive   jsonb       NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz NULL,
    acked_at    timestamptz NULL
);

-- Pending queue per attempt, oldest first.
CREATE INDEX environment_directives_pending_idx
    ON environment_directives (attempt_id, created_at)
    WHERE acked_at IS NULL;

ALTER TABLE attempts ADD COLUMN last_heartbeat_journaled_at timestamptz NULL;

-- V5b: latest runnerd progress per category without scanning the attempt.
CREATE INDEX session_events_attempt_kind_category_idx
    ON session_events (attempt_id, kind, ((data ->> 'category')));
