package com.iacagent.iacagent.runner;

/**
 * Deliberately contains no APPLYING/APPLIED/MUTATED state - Phase 2B-1 grants no mutation
 * authority, so no state exists to represent one. {@code READY_FOR_FUTURE_EXECUTION} is as far as
 * this phase's state machine goes; a later phase, not this enum being extended casually, is what
 * would ever move past it.
 */
public enum RunnerState {
    RECEIVED,
    IDENTITY_RESOLVED,
    APPROVAL_RESOLVED,
    ARTIFACT_RESOLVED,
    ARTIFACT_VERIFIED,
    CONTEXT_VERIFIED,
    READY_FOR_FUTURE_EXECUTION,
    BLOCKED,
    FAILED
}
