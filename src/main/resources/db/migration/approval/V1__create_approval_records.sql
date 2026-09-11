-- Phase 2C-2: durable authoritative approval store.
-- Deliberately no indexes beyond the primary key: every current lookup (ApprovalProvider.resolve,
-- revoke, supersede) is by approval_id alone, which the primary key already covers. Supersession
-- is caller-declared, not discovered by a repository/environment/commit query, so no index exists
-- to support that kind of lookup - see ApprovalRecordProducer's javadoc for why.
CREATE TABLE approval_records (
    approval_id VARCHAR PRIMARY KEY,
    repository VARCHAR NOT NULL,
    commit_sha VARCHAR NOT NULL,
    environment VARCHAR NOT NULL,
    plan_sha256 VARCHAR NOT NULL,

    approved_by VARCHAR NOT NULL,
    approved_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    status VARCHAR NOT NULL,

    reviewed_pr_reference VARCHAR,
    ci_run_reference VARCHAR,

    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by VARCHAR,
    revocation_reason VARCHAR,

    superseded_at TIMESTAMP WITH TIME ZONE,
    superseded_by_approval_id VARCHAR,
    superseding_plan_sha256 VARCHAR,

    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT chk_approval_status CHECK (status IN ('ACTIVE', 'REVOKED', 'SUPERSEDED')),
    CONSTRAINT chk_approval_expiry CHECK (expires_at > approved_at)
);
