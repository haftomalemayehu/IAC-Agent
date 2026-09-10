package com.iacagent.iacagent.approval;

public enum ApprovalValidationReasonCode {
    VALID,
    APPROVAL_NOT_FOUND,
    REPOSITORY_MISMATCH,
    COMMIT_SHA_MISMATCH,
    ENVIRONMENT_MISMATCH,
    PLAN_HASH_MISMATCH,
    APPROVAL_REVOKED,
    APPROVAL_SUPERSEDED,
    APPROVAL_EXPIRED
}
