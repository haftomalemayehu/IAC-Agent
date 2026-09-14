package com.iacagent.iacagent.runner.jdbc;

import java.time.Instant;

/** One sanitized observability event - see {@link RunnerLedgerObserver}. {@code runnerRequestId}
 * may be {@code null} for {@link RunnerLedgerEventType#DATABASE_UNAVAILABLE} when the failure
 * occurred before any id-specific work began (e.g. connection acquisition itself failed). */
public record RunnerLedgerEvent(RunnerLedgerEventType type, String runnerRequestId, Instant at) {
    public RunnerLedgerEvent {
        if (type == null) {
            throw new IllegalArgumentException("type is required");
        }
        if (at == null) {
            throw new IllegalArgumentException("at is required");
        }
    }
}
