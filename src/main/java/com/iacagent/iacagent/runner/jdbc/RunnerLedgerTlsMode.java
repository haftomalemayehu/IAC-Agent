package com.iacagent.iacagent.runner.jdbc;

import java.util.Set;

/**
 * The TLS posture for a {@link PostgresRunnerLedgerRepository} connection, expressed as a value the
 * pgjdbc driver understands directly ({@code sslmode} connection property).
 *
 * <p>{@link #DISABLED_FOR_TESTS_ONLY} exists ONLY so test code (a Testcontainers instance with no
 * TLS listener) has an honestly-named way to request plaintext connectivity - it is structurally
 * impossible to reach from {@link PostgresRunnerLedgerConfig#fromProperties}, the sole production
 * configuration entry point, which calls {@link #parseProductionValue} and rejects this value (and
 * anything else) outside the three production-safe modes even if a caller tries to pass its name
 * through configuration.
 */
public enum RunnerLedgerTlsMode {
    /** Encrypted, but does not verify the server certificate against a CA - protects against a
     * passive eavesdropper, not an active machine-in-the-middle. The minimum accepted production
     * posture. */
    REQUIRE("require"),
    /** Encrypted and verifies the server certificate against a trusted CA, but does not verify the
     * server hostname matches the certificate. */
    VERIFY_CA("verify-ca"),
    /** Encrypted, verifies the server certificate against a trusted CA, AND verifies the server
     * hostname matches the certificate - the strongest posture pgjdbc supports. */
    VERIFY_FULL("verify-full"),
    /** Plaintext. Test-only - see class javadoc. */
    DISABLED_FOR_TESTS_ONLY("disable");

    private static final Set<RunnerLedgerTlsMode> PRODUCTION_SAFE = Set.of(REQUIRE, VERIFY_CA, VERIFY_FULL);

    private final String jdbcSslMode;

    RunnerLedgerTlsMode(String jdbcSslMode) {
        this.jdbcSslMode = jdbcSslMode;
    }

    /** The literal value to set as pgjdbc's {@code sslmode} connection property. */
    public String jdbcSslMode() {
        return jdbcSslMode;
    }

    public boolean isProductionSafe() {
        return PRODUCTION_SAFE.contains(this);
    }

    /** Parses a production configuration value - accepts ONLY {@code "require"}, {@code "verify-ca"},
     * or {@code "verify-full"} (case-insensitive). Never returns {@link #DISABLED_FOR_TESTS_ONLY},
     * regardless of what string is supplied - this is the enforcement point that makes plaintext
     * connectivity unreachable from production configuration. */
    public static RunnerLedgerTlsMode parseProductionValue(String raw) {
        if (raw != null) {
            for (RunnerLedgerTlsMode candidate : PRODUCTION_SAFE) {
                if (candidate.jdbcSslMode.equalsIgnoreCase(raw.trim())) {
                    return candidate;
                }
            }
        }
        throw new RunnerLedgerConfigurationException(
                "runner.ledger.postgres.sslMode must be one of require|verify-ca|verify-full for production use, got: " + raw);
    }
}
