package com.iacagent.iacagent.runner.jdbc;

/**
 * Thrown when production runner-ledger configuration is missing, malformed, or requests an unsafe
 * posture (e.g. a non-production-safe TLS mode) - always thrown BEFORE any {@link javax.sql.DataSource}
 * or connection pool is created, so a misconfigured deployment fails at startup rather than silently
 * falling back to H2/in-memory persistence or connecting insecurely. The message never contains a
 * credential value - only key names and the (non-secret) values that were rejected.
 */
public final class RunnerLedgerConfigurationException extends RuntimeException {
    public RunnerLedgerConfigurationException(String message) {
        super(message);
    }

    public RunnerLedgerConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
