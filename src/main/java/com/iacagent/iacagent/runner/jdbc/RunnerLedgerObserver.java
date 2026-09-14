package com.iacagent.iacagent.runner.jdbc;

/**
 * Sanitized structured-event sink for {@link PostgresRunnerLedgerRepository} - claim success,
 * duplicate, fingerprint mismatch, incomplete prior claim, completion, database unavailable, and
 * ambiguous result are each reported here. An implementation must never log, store, or otherwise
 * surface a database password, connection secret, or raw SQL parameter value - {@link RunnerLedgerEvent}
 * itself structurally cannot carry one (it has no field for it), so a compliant observer
 * implementation only has to avoid reaching outside the event object for anything sensitive.
 */
@FunctionalInterface
public interface RunnerLedgerObserver {

    void onEvent(RunnerLedgerEvent event);

    static RunnerLedgerObserver noOp() {
        return NoOpRunnerLedgerObserver.INSTANCE;
    }
}
