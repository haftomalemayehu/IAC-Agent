package com.iacagent.iacagent.runner;

/**
 * The outcome of {@link RunnerLedgerRepository#claim}. Deliberately does not include a
 * {@code STORAGE_FAILURE} value: a genuine infrastructure failure is signaled by throwing
 * {@link RunnerLedgerPersistenceException} instead, matching the approval subsystem's own
 * convention (an infra failure is a different kind of thing than a legitimate domain outcome, and
 * an exception cannot be silently missed the way a {@code default} branch of a switch could).
 *
 * <p>Also deliberately collapses "a concurrent claim is in progress right now" and "a prior claim
 * was made by a process that has since crashed without recording terminal evidence" into the SAME
 * outcome, {@link #INCOMPLETE_PRIOR_CLAIM}: both look identical in persisted state (a row exists
 * with {@link RunnerClaimState#CLAIMED}, no terminal evidence yet), and both call for the same
 * response - block, do not proceed, do not guess which case it is.
 */
public enum RunnerClaimOutcome {
    /** No prior row existed for this id; this call now exclusively owns it. */
    CLAIMED,
    /** A COMPLETED row exists for this id with the exact same request fingerprint. */
    DUPLICATE_SAME_FINGERPRINT,
    /** A row exists for this id (CLAIMED or COMPLETED) with a DIFFERENT request fingerprint. */
    FINGERPRINT_MISMATCH,
    /** A CLAIMED (not yet COMPLETED) row exists for this id with the same fingerprint. */
    INCOMPLETE_PRIOR_CLAIM
}
