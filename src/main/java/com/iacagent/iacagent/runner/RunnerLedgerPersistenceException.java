package com.iacagent.iacagent.runner;

/**
 * Thrown by a {@link RunnerLedgerRepository} implementation on genuine infrastructure failure
 * (database unavailable, transaction failure, connection loss). Mirrors
 * {@code com.iacagent.iacagent.approval.ApprovalPersistenceException} exactly: never caught and
 * converted into a false CLAIMED/COMPLETED outcome anywhere in this package, and never a signal
 * to fall back to an in-memory ledger. "Ledger unavailable" must block, not degrade.
 */
public class RunnerLedgerPersistenceException extends RuntimeException {
    public RunnerLedgerPersistenceException(String message, Throwable cause) {
        super(message, cause);
    }
}
