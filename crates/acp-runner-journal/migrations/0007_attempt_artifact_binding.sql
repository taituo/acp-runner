-- acp-runner journal schema v7 (V3a ingest integrity): the attempt's authoritative
-- artifact must belong to the same attempt in the same run. The application layer
-- verifies this before attaching; this trigger is defense in depth so a buggy caller
-- can never cross-link a foreign attempt's artifact (including a same-attempt id
-- recorded under a different run).

CREATE OR REPLACE FUNCTION check_attempt_artifact_binding() RETURNS trigger AS $$
BEGIN
    IF NEW.artifact_id IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM artifacts
            WHERE id = NEW.artifact_id AND attempt_id = NEW.id AND run_id = NEW.run_id
        ) THEN
            RAISE EXCEPTION 'attempts.artifact_id % does not belong to attempt % of run %', NEW.artifact_id, NEW.id, NEW.run_id
                USING ERRCODE = 'foreign_key_violation';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS attempts_artifact_binding ON attempts;
CREATE TRIGGER attempts_artifact_binding
    BEFORE INSERT OR UPDATE OF artifact_id ON attempts
    FOR EACH ROW EXECUTE FUNCTION check_attempt_artifact_binding();
