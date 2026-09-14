package com.iacagent.iacagent.runner.jdbc;

/** The fixed, sanitized set of observability events {@link PostgresRunnerLedgerRepository} emits -
 * see {@link RunnerLedgerObserver}. Never carries a database password, connection secret, or raw
 * SQL parameter value; only the event type, the (non-secret) {@code runnerRequestId}, and a
 * timestamp. */
public enum RunnerLedgerEventType {
    CLAIM_SUCCESS,
    DUPLICATE,
    FINGERPRINT_MISMATCH,
    INCOMPLETE_PRIOR_CLAIM,
    COMPLETION,
    DATABASE_UNAVAILABLE,
    AMBIGUOUS_RESULT
}
