-- acp-runner journal schema v5 (v3 provider layer, part 2): workspace lineage and bundles.
--
-- Artifacts stay cumulative against the original base; lineage is metadata:
--   B1 = diff(base, state B), B1.parent_artifact_id = S1, B1.parent_environment_id = A.
ALTER TABLE artifacts
    ADD COLUMN environment_id        uuid NULL,
    ADD COLUMN parent_artifact_id    uuid NULL,
    ADD COLUMN parent_environment_id uuid NULL;
CREATE INDEX artifacts_environment_idx ON artifacts (environment_id) WHERE environment_id IS NOT NULL;
CREATE INDEX artifacts_parent_idx ON artifacts (parent_artifact_id) WHERE parent_artifact_id IS NOT NULL;

ALTER TABLE environments
    ADD COLUMN parent_artifact_id    uuid NULL,
    ADD COLUMN parent_environment_id uuid NULL;
CREATE INDEX environments_attempt_idx ON environments (attempt_id);

-- Resolved bundles (configs / agents / skills), content-addressed. Non-secret by contract:
-- bundles are configuration, credentials never travel as bundles.
CREATE TABLE bundles (
    digest      text PRIMARY KEY,               -- sha256:<hex> over kind, name, files
    kind        text        NOT NULL,           -- config | agent | skill
    name        text        NOT NULL,
    metadata    jsonb       NOT NULL,
    manifest    jsonb       NOT NULL,           -- [{path, mode, bytes, sha256}]
    size_bytes  bigint      NOT NULL,
    content     jsonb       NOT NULL,           -- the Bundle document (base64 file content)
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX bundles_name_idx ON bundles (kind, name);
