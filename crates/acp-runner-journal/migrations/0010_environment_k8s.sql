-- V10a/V10b: controller mapping for AgentEnvironment + ticket key version.
--
-- The controller maps each AgentEnvironment object to its journal row by
-- (namespace, name); `k8s_uid` guards against a deleted-then-recreated object
-- reusing the name (UID mismatch => the row is stale and must be destroyed
-- before a fresh row takes the name). `key_version` selects the ticket master
-- key a live environment's connection tickets are minted with (V10b rotation:
-- new environments use the current key, existing ones keep theirs).
ALTER TABLE environments
    ADD COLUMN k8s_namespace TEXT NULL,
    ADD COLUMN k8s_name TEXT NULL,
    ADD COLUMN k8s_uid TEXT NULL,
    ADD COLUMN key_version TEXT NOT NULL DEFAULT 'v1';
-- At most one live row per object name; terminal rows stay as history.
CREATE UNIQUE INDEX environments_k8s_live_idx ON environments (k8s_namespace, k8s_name)
    WHERE k8s_namespace IS NOT NULL AND phase NOT IN ('Completed', 'Failed');
