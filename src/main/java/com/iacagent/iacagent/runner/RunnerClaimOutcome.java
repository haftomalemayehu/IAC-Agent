package com.iacagent.iacagent.runner;

/**
 * The outcome of {@link RunnerLedgerRepository#claim}. Deliberately does not include a
 * {@code STORAGE_FAILURE} value: a genuine, UNAMBIGUOUS infrastructure failure (the claim attempt
 * never reached the database at all - e.g. connection acquisition itself failed) is signaled by
 * throwing {@link RunnerLedgerPersistenceException} instead, matching the approval subsystem's own
 * convention (an infra failure is a different kind of thing than a legitimate domain outcome, and
 * an exception cannot be silently missed the way a {@code default} branch of a switch could).
 *
 * <p>Also deliberately collapses "a concurrent claim is in progress right now" and "a prior claim
 * was made by a process that has since crashed without recording terminal evidence" into the SAME
 * outcome, {@link #INCOMPLETE_PRIOR_CLAIM}: both look identical in persisted state (a row exists
 * with {@link RunnerClaimState#CLAIMED}, no terminal evidence yet), and both call for the same
 * response - block, do not proceed, do not guess which case it is.
 *
 * <p>{@link #AMBIGUOUS} (Phase 2B-6) is the third, distinct kind of thing: the claim's own mutating
 * statement WAS sent to the database, but this caller lost the ability to observe whether it
 * committed (e.g. the connection broke while awaiting the server's acknowledgment). This is neither
 * "definitely claimed" nor "definitely not claimed" - treating it as either would be unsafe (the
 * former could grant execution to two callers if it actually failed; the latter could let this same
 * caller, or worse a caller who assumes ambiguity means "safe to retry as a fresh claim," believe no
 * claim exists when one may already have committed). A fresh subsequent {@code claim()} call for the
 * SAME {@code runnerRequestId} - not any special reconciliation logic inside the ambiguous attempt
 * itself - is what safely resolves this: it will observe {@code CLAIMED} if the ambiguous attempt
 * genuinely never committed, or the correct duplicate/incomplete outcome if it did.
 */
public enum RunnerClaimOutcome {
    /** No prior row existed for this id; this call now exclusively owns it. */
    CLAIMED,
    /** A COMPLETED row exists for this id with the exact same request fingerprint. */
    DUPLICATE_SAME_FINGERPRINT,
    /** A row exists for this id (CLAIMED or COMPLETED) with a DIFFERENT request fingerprint. */
    FINGERPRINT_MISMATCH,
    /** A CLAIMED (not yet COMPLETED) row exists for this id with the same fingerprint. */
    INCOMPLETE_PRIOR_CLAIM,
    /** The claim's mutating statement was transmitted to the database, but this caller could not
     * observe its outcome (see class javadoc). Must never be treated as {@link #CLAIMED}, must
     * never be silently retried by the repository itself, and must never be interpreted as "no
     * claim exists" - the caller (see {@code ControlledRunner}) must block. */
    AMBIGUOUS
}
