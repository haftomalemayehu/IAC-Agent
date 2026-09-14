-- Phase 2B-6: production runner ledger schema for PostgresRunnerLedgerRepository.
--
-- Deliberately a SEPARATE Flyway history/location from db/migration/runner (the H2
-- reference/test schema) rather than a shared migration path: the two targets have real dialect
-- differences (JSONB + a trigger-enforced immutability guard here, neither meaningful on H2) and
-- are versioned independently on purpose - a schema change to one must never be assumed to apply to
-- the other. This migration is written for a NEW PostgreSQL deployment; it does not need to be
-- compatible with, or a migration of, the existing H2 runner_requests table.
--
-- Column naming intentionally differs from the H2 schema's runner_request_id/claim_state
-- (request_id/state here) - there is no shared consumer of both schemas' column names, so nothing
-- is gained by forcing them to match, and the shorter names read better against the SQL in
-- PostgresRunnerLedgerRepository.

CREATE TABLE runner_requests (
    request_id                  TEXT PRIMARY KEY,
    fingerprint                 TEXT NOT NULL,

    -- Immutable identity fields, set once at claim time and never rewritten - enforced both by
    -- application code (only one UPDATE statement exists anywhere in this repository, and it never
    -- touches these columns) and, defense-in-depth, by the trigger below.
    repository                  TEXT NOT NULL,
    commit_sha                  TEXT NOT NULL,
    environment                 TEXT NOT NULL,
    plan_artifact_id            TEXT NOT NULL,
    plan_sha256                 TEXT NOT NULL,
    terraform_version_expected  TEXT NOT NULL,
    provider_lock_hash_expected TEXT NOT NULL,
    approval_id                 TEXT NOT NULL,
    requested_operation         TEXT NOT NULL,

    state                       TEXT NOT NULL CHECK (state IN ('CLAIMED', 'COMPLETED')),

    -- Populated only at completion; NULL for the lifetime of CLAIMED.
    runner_id                   TEXT,
    runner_class                TEXT,
    runner_environment_scope    TEXT,
    observed_plan_sha256        TEXT,
    terraform_version_observed  TEXT,
    provider_lock_hash_observed TEXT,
    approval_validation_result  TEXT,
    final_state                 TEXT,
    reason_codes                TEXT,

    -- JSONB (not TEXT): the database itself validates well-formedness at write time, and this is
    -- the one place in this schema an actual dialect difference from the H2 reference is genuinely
    -- justified rather than cosmetic.
    terraform_process_evidence         JSONB,
    terraform_init_evidence            JSONB,
    terraform_validate_evidence        JSONB,
    terraform_provider_schema_evidence JSONB,
    terraform_plan_evidence            JSONB,

    claimed_at                  TIMESTAMPTZ NOT NULL,
    completed_at                TIMESTAMPTZ,

    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- "completed_at consistent with state": CLAIMED rows never have one, COMPLETED rows always do.
    CONSTRAINT chk_completed_at_consistent_with_state CHECK (
        (state = 'CLAIMED' AND completed_at IS NULL) OR
        (state = 'COMPLETED' AND completed_at IS NOT NULL)
    )
);

-- No indexes beyond the primary key: every query in PostgresRunnerLedgerRepository (claim,
-- recordTerminalEvidence, findHistoricalEvidence) looks up by request_id alone, already
-- PK-covered - an additional index here would be exactly the kind of unjustified addition the
-- authorization warned against.

-- Database-enforced transition guard, in addition to (not instead of) the application-level
-- guarded UPDATE in PostgresRunnerLedgerRepository#recordTerminalEvidence. This is "mechanically
-- necessary" per the authorization's own bar for adding anything beyond the two-state CLAIMED/
-- COMPLETED model: a CHECK constraint cannot reference a row's OLD value, so the ONLY way to make
-- "COMPLETED is terminal and immutable" and "identity/fingerprint/claimed_at never change" a
-- database-enforced fact - not merely an application-code convention - is a BEFORE UPDATE trigger.
CREATE FUNCTION runner_requests_guard_transition() RETURNS trigger AS $$
BEGIN
    IF OLD.state = 'COMPLETED' THEN
        RAISE EXCEPTION 'runner_requests row % is COMPLETED and immutable - no further update is permitted', OLD.request_id
            USING ERRCODE = '25000';
    END IF;
    IF NEW.request_id              IS DISTINCT FROM OLD.request_id
        OR NEW.fingerprint          IS DISTINCT FROM OLD.fingerprint
        OR NEW.repository           IS DISTINCT FROM OLD.repository
        OR NEW.commit_sha           IS DISTINCT FROM OLD.commit_sha
        OR NEW.environment          IS DISTINCT FROM OLD.environment
        OR NEW.plan_artifact_id     IS DISTINCT FROM OLD.plan_artifact_id
        OR NEW.plan_sha256          IS DISTINCT FROM OLD.plan_sha256
        OR NEW.terraform_version_expected  IS DISTINCT FROM OLD.terraform_version_expected
        OR NEW.provider_lock_hash_expected IS DISTINCT FROM OLD.provider_lock_hash_expected
        OR NEW.approval_id          IS DISTINCT FROM OLD.approval_id
        OR NEW.requested_operation  IS DISTINCT FROM OLD.requested_operation
        OR NEW.claimed_at           IS DISTINCT FROM OLD.claimed_at
    THEN
        RAISE EXCEPTION 'runner_requests row % - identity/fingerprint/claimed_at fields are immutable after claim', OLD.request_id
            USING ERRCODE = '25000';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_runner_requests_guard_transition
    BEFORE UPDATE ON runner_requests
    FOR EACH ROW
    EXECUTE FUNCTION runner_requests_guard_transition();
