package com.iacagent.iacagent.runner.jdbc;

import java.util.Map;
import java.util.regex.Pattern;

/**
 * Everything {@link PostgresRunnerLedgerRepository} needs to connect to production PostgreSQL,
 * validated eagerly (fail closed at construction, never at first use) and printable
 * ({@link #toString()}) without ever revealing the credential value. The credential itself is never
 * a field here - only a {@link RunnerLedgerCredentialSource} that resolves it on demand.
 *
 * <p>{@link #fromProperties} is the sole production configuration entry point (see
 * {@link RunnerLedgerConfiguration}): every required key must be present and valid, or construction
 * throws {@link RunnerLedgerConfigurationException} - there is no partial/default configuration that
 * lets a deployment start with, say, TLS silently disabled or an unbounded pool.
 */
public record PostgresRunnerLedgerConfig(
        String jdbcUrl,
        String username,
        RunnerLedgerCredentialSource credentialSource,
        RunnerLedgerTlsMode tlsMode,
        int minPoolSize,
        int maxPoolSize,
        long connectionTimeoutMillis,
        long statementTimeoutMillis
) {
    private static final Pattern PASSWORD_QUERY_PARAM = Pattern.compile("(?i)(password=)[^&]*");

    public PostgresRunnerLedgerConfig {
        if (jdbcUrl == null || !jdbcUrl.startsWith("jdbc:postgresql:")) {
            throw new RunnerLedgerConfigurationException("jdbcUrl must be a jdbc:postgresql:... URL, got: " + redactJdbcUrl(jdbcUrl));
        }
        if (username == null || username.isBlank()) {
            throw new RunnerLedgerConfigurationException("username is required");
        }
        if (credentialSource == null) {
            throw new RunnerLedgerConfigurationException("credentialSource is required");
        }
        if (tlsMode == null) {
            throw new RunnerLedgerConfigurationException("tlsMode is required");
        }
        if (minPoolSize < 1) {
            throw new RunnerLedgerConfigurationException("minPoolSize must be >= 1, got: " + minPoolSize);
        }
        if (maxPoolSize < minPoolSize) {
            throw new RunnerLedgerConfigurationException("maxPoolSize (" + maxPoolSize + ") must be >= minPoolSize (" + minPoolSize + ")");
        }
        if (maxPoolSize > 100) {
            // A stuck/misbehaving database must fail closed quickly, not hold arbitrarily many
            // connections open - an unbounded pool is itself a resource-exhaustion risk.
            throw new RunnerLedgerConfigurationException("maxPoolSize must be <= 100, got: " + maxPoolSize);
        }
        if (connectionTimeoutMillis < 250 || connectionTimeoutMillis > 60_000) {
            throw new RunnerLedgerConfigurationException(
                    "connectionTimeoutMillis must be between 250 and 60000, got: " + connectionTimeoutMillis);
        }
        if (statementTimeoutMillis < 250 || statementTimeoutMillis > 300_000) {
            throw new RunnerLedgerConfigurationException(
                    "statementTimeoutMillis must be between 250 and 300000, got: " + statementTimeoutMillis);
        }
    }

    /** Parses production configuration from a flat property map (e.g. Spring {@code Environment}
     * properties, or a plain {@link java.util.Properties} adapted to {@code Map<String,String>}).
     * Required keys, all under the {@code runner.ledger.postgres.} prefix:
     * <pre>
     * jdbcUrl                  - jdbc:postgresql://host:port/database
     * username
     * passwordEnvVar           - name of the environment variable holding the password; the value
     *                            itself is never read from this property map
     * sslMode                  - require | verify-ca | verify-full (case-insensitive)
     * minPoolSize / maxPoolSize
     * connectionTimeoutMillis
     * statementTimeoutMillis
     * </pre>
     * Any missing or invalid key throws {@link RunnerLedgerConfigurationException} - there is no
     * default for any of these. */
    public static PostgresRunnerLedgerConfig fromProperties(Map<String, String> properties) {
        if (properties == null) {
            throw new RunnerLedgerConfigurationException("properties map is required");
        }
        String jdbcUrl = requireProperty(properties, "runner.ledger.postgres.jdbcUrl");
        String username = requireProperty(properties, "runner.ledger.postgres.username");
        String passwordEnvVar = requireProperty(properties, "runner.ledger.postgres.passwordEnvVar");
        RunnerLedgerTlsMode tlsMode = RunnerLedgerTlsMode.parseProductionValue(
                requireProperty(properties, "runner.ledger.postgres.sslMode"));
        int minPoolSize = requireInt(properties, "runner.ledger.postgres.minPoolSize");
        int maxPoolSize = requireInt(properties, "runner.ledger.postgres.maxPoolSize");
        long connectionTimeoutMillis = requireLong(properties, "runner.ledger.postgres.connectionTimeoutMillis");
        long statementTimeoutMillis = requireLong(properties, "runner.ledger.postgres.statementTimeoutMillis");

        return new PostgresRunnerLedgerConfig(
                jdbcUrl, username, RunnerLedgerCredentialSource.fromEnvironmentVariable(passwordEnvVar),
                tlsMode, minPoolSize, maxPoolSize, connectionTimeoutMillis, statementTimeoutMillis);
    }

    /** Test-only construction - bypasses {@link #fromProperties} entirely (never reachable from
     * production configuration parsing) and always uses {@link RunnerLedgerTlsMode#DISABLED_FOR_TESTS_ONLY},
     * since a Testcontainers PostgreSQL instance has no TLS listener. Named accordingly so its
     * purpose is unmistakable at every call site. */
    public static PostgresRunnerLedgerConfig forTests(String jdbcUrl, String username, String password) {
        return new PostgresRunnerLedgerConfig(
                jdbcUrl, username, RunnerLedgerCredentialSource.forTests(password),
                RunnerLedgerTlsMode.DISABLED_FOR_TESTS_ONLY, 1, 8, 5_000, 10_000);
    }

    /** Never includes the credential - only non-secret connectivity/pool parameters, with the
     * JDBC URL itself defensively redacted in case a caller ever embeds {@code password=} in it
     * (this class never does, but a hostile/malformed URL string should still never leak one). */
    @Override
    public String toString() {
        return "PostgresRunnerLedgerConfig{"
                + "jdbcUrl=" + redactJdbcUrl(jdbcUrl)
                + ", username=" + username
                + ", tlsMode=" + tlsMode
                + ", minPoolSize=" + minPoolSize
                + ", maxPoolSize=" + maxPoolSize
                + ", connectionTimeoutMillis=" + connectionTimeoutMillis
                + ", statementTimeoutMillis=" + statementTimeoutMillis
                + "}";
    }

    private static String redactJdbcUrl(String url) {
        if (url == null) {
            return "null";
        }
        return PASSWORD_QUERY_PARAM.matcher(url).replaceAll("$1REDACTED");
    }

    private static String requireProperty(Map<String, String> properties, String key) {
        String value = properties.get(key);
        if (value == null || value.isBlank()) {
            throw new RunnerLedgerConfigurationException("required configuration property is missing: " + key);
        }
        return value;
    }

    private static int requireInt(Map<String, String> properties, String key) {
        String raw = requireProperty(properties, key);
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            throw new RunnerLedgerConfigurationException("configuration property " + key + " must be an integer, got: " + raw);
        }
    }

    private static long requireLong(Map<String, String> properties, String key) {
        String raw = requireProperty(properties, key);
        try {
            return Long.parseLong(raw.trim());
        } catch (NumberFormatException e) {
            throw new RunnerLedgerConfigurationException("configuration property " + key + " must be an integer, got: " + raw);
        }
    }
}
