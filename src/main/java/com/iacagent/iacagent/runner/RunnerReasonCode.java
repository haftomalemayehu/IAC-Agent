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
    RUNNER_REQUEST_FINGERPRINT_MISMATCH,
    /** The durable {@link RunnerLedgerRepository} could not be reached or threw an infrastructure
     * failure. Never converted into any other outcome - "ledger unavailable" always blocks. */
    RUNNER_LEDGER_UNAVAILABLE,
    /** A ledger row exists for this {@code runnerRequestId} in {@link RunnerClaimState#CLAIMED}
     * (never reached {@code COMPLETED}) with the same fingerprint - either a concurrent claim is
     * genuinely in progress right now, or a prior process crashed after claiming but before
     * recording terminal evidence. Both look identical in persisted state and get this same,
     * conservative response; retrying the same id automatically is never attempted. */
    RUNNER_REQUEST_INCOMPLETE,
    /** {@link RunnerIdentityProvider#currentIdentity()} returned no identity at all (host
     * attestation source missing, unreadable, or malformed) - distinct from
     * {@link #RUNNER_IDENTITY_UNTRUSTED}, which means an identity WAS resolved but is marked
     * untrusted. */
    RUNNER_IDENTITY_UNAVAILABLE,
    /** The resolved runner identity's {@code runnerClass} is not in this ControlledRunner
     * instance's configured allowlist for the requested operation. */
    RUNNER_CLASS_NOT_ALLOWED,
    /** Workspace creation or isolation verification failed (e.g. the computed path did not stay
     * under the configured root, or a filesystem error occurred while staging). */
    WORKSPACE_ISOLATION_FAILURE,
    /** Artifact staging into the workspace failed for a reason other than a hash mismatch (already
     * covered by {@link #ARTIFACT_HASH_MISMATCH}) - e.g. an I/O failure while writing the staged
     * file. */
    ARTIFACT_STAGING_FAILURE
}
