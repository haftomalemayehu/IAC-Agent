-- Phase 2B-2: durable runner request/evidence ledger.
-- No indexes beyond the primary key: every lookup (claim, recordTerminalEvidence,
-- findHistoricalEvidence) is by runner_request_id alone, already PK-covered.
CREATE TABLE runner_requests (
    runner_request_id VARCHAR PRIMARY KEY,
    request_fingerprint VARCHAR NOT NULL,

    repository VARCHAR NOT NULL,
    commit_sha VARCHAR NOT NULL,
    environment VARCHAR NOT NULL,
    plan_artifact_id VARCHAR NOT NULL,
    plan_sha256 VARCHAR NOT NULL,
    terraform_version_expected VARCHAR NOT NULL,
    provider_lock_hash_expected VARCHAR NOT NULL,
    approval_id VARCHAR NOT NULL,
    requested_operation VARCHAR NOT NULL,

    claim_state VARCHAR NOT NULL,

    runner_id VARCHAR,
    runner_class VARCHAR,
    runner_environment_scope VARCHAR,

    observed_plan_sha256 VARCHAR,
    terraform_version_observed VARCHAR,
    provider_lock_hash_observed VARCHAR,
    approval_validation_result VARCHAR,

    final_state VARCHAR,
    reason_codes VARCHAR,

    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,

    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT chk_runner_claim_state CHECK (claim_state IN ('CLAIMED', 'COMPLETED'))
);
