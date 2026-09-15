package com.iacagent.iacagent.identity;

import com.iacagent.iacagent.runner.RunnerReasonCode;

/**
 * Thrown when ANY step of verify → authorize → federate fails - carries the precise
 * {@link RunnerReasonCode} the failure corresponds to, and optionally a sanitized
 * {@link WorkloadIdentityEvidence} snapshot of what was known before the failure (for audit), never
 * the raw token or any credential material. Never carries a raw token, raw credential value, or
 * any exception message containing either - {@link Throwable#getMessage()} is safe to log/surface
 * on every instance this codebase constructs.
 */
public final class WorkloadIdentityFederationException extends RuntimeException {
    private final RunnerReasonCode reasonCode;
    private final WorkloadIdentityEvidence evidence;

    public WorkloadIdentityFederationException(RunnerReasonCode reasonCode, String message) {
        this(reasonCode, message, (WorkloadIdentityEvidence) null);
    }

    public WorkloadIdentityFederationException(RunnerReasonCode reasonCode, String message, WorkloadIdentityEvidence evidence) {
        super(message);
        if (reasonCode == null) {
            throw new IllegalArgumentException("reasonCode is required");
        }
        this.reasonCode = reasonCode;
        this.evidence = evidence;
    }

    /** {@code cause}'s message is never surfaced beyond this exception's own stack trace context -
     * callers must still only report {@link #reasonCode()}/{@link #getMessage()} in evidence, never
     * walk {@link #getCause()} into anything persisted. */
    public WorkloadIdentityFederationException(RunnerReasonCode reasonCode, String message, Throwable cause) {
        super(message, cause);
        if (reasonCode == null) {
            throw new IllegalArgumentException("reasonCode is required");
        }
        this.reasonCode = reasonCode;
        this.evidence = null;
    }

    public RunnerReasonCode reasonCode() {
        return reasonCode;
    }

    /** May be {@code null} if the failure occurred before enough was known to build even a partial
     * evidence snapshot (e.g. no token was ever obtained). */
    public WorkloadIdentityEvidence evidence() {
        return evidence;
    }
}
