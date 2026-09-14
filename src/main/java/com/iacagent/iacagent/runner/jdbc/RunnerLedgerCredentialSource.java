package com.iacagent.iacagent.runner.jdbc;

/**
 * A trusted source of the production runner ledger's database credential - deliberately a supplier
 * abstraction rather than a plain {@code String password} field on {@link PostgresRunnerLedgerConfig},
 * for the same reason {@code com.iacagent.iacagent.runner.TerraformCredentialProvider} exists
 * elsewhere in this package: the raw secret should have exactly one owner (whatever resolves it -
 * an environment variable, a mounted secret file, a future secrets-manager client) and should never
 * sit in a plain field a stray {@code toString()}/log statement/serialized diagnostic dump could
 * accidentally surface. Implementations must never log, cache-and-print, or otherwise expose the
 * value they return.
 */
@FunctionalInterface
public interface RunnerLedgerCredentialSource {

    /** Resolves the current password. Called once per new physical connection the pool opens -
     * never stored by {@link PostgresRunnerLedgerConfig} or {@link PostgresRunnerLedgerRepository}
     * beyond the immediate call into the JDBC driver/connection pool. */
    String password();

    /** A fixed-value source - explicitly named "forTests" because a literal in-process password is
     * never appropriate for how a real production credential should be resolved (a secrets manager,
     * an environment variable populated by the orchestration platform, etc.) - this exists only so
     * test code has an obvious, honestly-named way to supply one. */
    static RunnerLedgerCredentialSource forTests(String fixedPassword) {
        if (fixedPassword == null) {
            throw new IllegalArgumentException("fixedPassword is required");
        }
        return () -> fixedPassword;
    }

    /** Resolves the password from an environment variable at call time (never cached) - the
     * minimum production-appropriate source this module ships: the actual secret value never
     * appears in source, configuration files, or command-line arguments, and each connection
     * re-reads it rather than trusting a value captured once at startup. */
    static RunnerLedgerCredentialSource fromEnvironmentVariable(String variableName) {
        if (variableName == null || variableName.isBlank()) {
            throw new IllegalArgumentException("variableName is required");
        }
        return () -> {
            String value = System.getenv(variableName);
            if (value == null || value.isBlank()) {
                throw new RunnerLedgerConfigurationException(
                        "required credential environment variable is not set: " + variableName);
            }
            return value;
        };
    }
}
