package com.iacagent.iacagent.approval;

/**
 * ACTIVE, REVOKED, and SUPERSEDED are persisted states, written by an explicit transition
 * (ApprovalRepository#revoke / #supersede). EXPIRED is never written to storage - it is only
 * ever returned by {@link ApprovalRecord#effectiveStatus(java.time.Instant)}, computed by
 * comparing a persisted ACTIVE record's expiresAt against the current time. Callers must use
 * effectiveStatus(), never the raw persisted status alone, or they will treat a timed-out
 * approval as still ACTIVE.
 */
public enum ApprovalStatus {
    ACTIVE,
    REVOKED,
    SUPERSEDED,
    EXPIRED
}
