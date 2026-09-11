package com.iacagent.iacagent.runner;

/**
 * Deterministic failure reasons. There is no generic "ERROR" value - every BLOCKED/FAILED outcome
 * this package produces carries one of these, never a bare exception message surfaced as if it
 * were the reason.
 */
public enum RunnerReasonCode {
    RUNNER_IDENTITY_UNTRUSTED,
    RUNNER_ENVIRONMENT_NOT_ALLOWED,
    APPROVAL_NOT_FOUND,
    APPROVAL_INVALID,
    APPROVAL_EXPIRED,
    APPROVAL_REVOKED,
    APPROVAL_SUPERSEDED,
    REPOSITORY_MISMATCH,
    COMMIT_SHA_MISMATCH,
    ENVIRONMENT_MISMATCH,
    PLAN_HASH_MISMATCH,
    ARTIFACT_NOT_FOUND,
    ARTIFACT_HASH_MISMATCH,
    TERRAFORM_VERSION_MISMATCH,
    PROVIDER_LOCK_HASH_MISMATCH,
    /** The requested operation cannot proceed as asked - operation authorization only. Never used
     * for request-id replay/collision; see {@link #DUPLICATE_RUNNER_REQUEST} and
     * {@link #RUNNER_REQUEST_FINGERPRINT_MISMATCH} for those. */
    OPERATION_NOT_ALLOWED,
    DURABLE_APPROVAL_STORE_UNAVAILABLE,
    /** A {@code runnerRequestId} was resubmitted with byte-for-byte identical request content.
     * The original evidence remains the authoritative historical record; this resubmission is
     * blocked rather than re-executed or replayed, because authorization state (approval validity,
     * expiry) can have changed since the original submission - see {@link ControlledRunner}. */
    DUPLICATE_RUNNER_REQUEST,
    /** A {@code runnerRequestId} was resubmitted with request content that differs from the
     * original submission under that same id - the same id must never represent two different
     * execution contexts. */
    RUNNER_REQUEST_FINGERPRINT_MISMATCH
}
