package com.iacagent.iacagent.runner.jdbc;

/** The default {@link RunnerLedgerObserver} - discards every event. Used whenever a caller does not
 * supply its own observer, so observability is additive/optional, never a required wiring step to
 * get a working {@link PostgresRunnerLedgerRepository}. */
final class NoOpRunnerLedgerObserver implements RunnerLedgerObserver {
    static final NoOpRunnerLedgerObserver INSTANCE = new NoOpRunnerLedgerObserver();

    private NoOpRunnerLedgerObserver() {
    }

    @Override
    public void onEvent(RunnerLedgerEvent event) {
        // discarded by design
    }
}
