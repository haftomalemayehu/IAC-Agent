package com.iacagent.iacagent.runner.jdbc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** A production-appropriate {@link RunnerLedgerObserver}: logs each sanitized event at a level
 * matching its severity (claim success/completion at INFO, mismatch/incomplete/ambiguous at WARN,
 * database unavailable at ERROR). Only ever logs the event's own fields - never reaches into
 * {@link PostgresRunnerLedgerConfig} or any connection/credential object, so there is nothing here
 * that could leak a secret regardless of log level or appender configuration. */
public final class Slf4jRunnerLedgerObserver implements RunnerLedgerObserver {
    private static final Logger LOG = LoggerFactory.getLogger(Slf4jRunnerLedgerObserver.class);

    @Override
    public void onEvent(RunnerLedgerEvent event) {
        switch (event.type()) {
            case CLAIM_SUCCESS, COMPLETION ->
                    LOG.info("runner-ledger event={} runnerRequestId={} at={}", event.type(), event.runnerRequestId(), event.at());
            case DUPLICATE, FINGERPRINT_MISMATCH, INCOMPLETE_PRIOR_CLAIM, AMBIGUOUS_RESULT ->
                    LOG.warn("runner-ledger event={} runnerRequestId={} at={}", event.type(), event.runnerRequestId(), event.at());
            case DATABASE_UNAVAILABLE ->
                    LOG.error("runner-ledger event={} runnerRequestId={} at={}", event.type(), event.runnerRequestId(), event.at());
        }
    }
}
