package com.iacagent.iacagent.approval;

/**
 * Result of an atomic compare-and-set state transition (ACTIVE -&gt; REVOKED or
 * ACTIVE -&gt; SUPERSEDED) attempted against an ApprovalRecord.
 */
public enum TransitionOutcome {
    /** This call performed the transition; it is the exclusive winner of any race. */
    SUCCESS,
    /** No record exists for the given approvalId. */
    NOT_FOUND,
    /**
     * The record was not ACTIVE at the moment of the compare-and-set - either it was already
     * REVOKED/SUPERSEDED (possibly by a concurrent call that won the race), or it is EXPIRED.
     * This is not itself an error: for a concurrent race, exactly one caller gets SUCCESS and
     * every other concurrent caller gets ALREADY_TRANSITIONED - that is the intended, safe
     * outcome, not a failure to be retried.
     */
    ALREADY_TRANSITIONED
}
