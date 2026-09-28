-- acp-runner journal schema v4 (v3 provider layer, part 1): the environment dataplane is
-- authenticated with signed, short-lived connection tickets derived from the provider master
-- key. Nothing token-like is stored any more.
ALTER TABLE environments ALTER COLUMN gateway_token_sha256 DROP NOT NULL;
