-- acp-runner journal migration 0008 (V2 trust boundary): per-profile usage policy.
--
-- A credential profile is lent only to attempts whose namespace and runner
-- class are both explicitly granted. Empty lists deny everything (deny by
-- default): pre-existing profiles stop working until an admin assigns them,
-- which is the intended secure migration for a security fix.
ALTER TABLE credential_profiles
    ADD COLUMN allowed_namespaces text[] NOT NULL DEFAULT '{}',
    ADD COLUMN allowed_classes    text[] NOT NULL DEFAULT '{}';
