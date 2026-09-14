package com.iacagent.iacagent.runner.jdbc;

import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Resolves which real PostgreSQL instance the {@code postgresTest} acceptance suite targets.
 *
 * <p>By default, each test class manages its own Testcontainers-launched {@link PostgreSQLContainer}
 * - the normal, portable way this suite is meant to run (any standard Linux CI with a working Docker
 * daemon). If the system properties {@code pgtest.jdbcUrl}/{@code pgtest.username}/{@code pgtest.password}
 * are all set, this class targets that EXTERNAL, already-running PostgreSQL instance instead, and
 * never starts/stops a Testcontainers container at all - this exists solely for environments where
 * Testcontainers' own Docker API client cannot obtain a valid daemon handle even though a real
 * Docker daemon and `docker` CLI are fully functional (observed in one sandbox during Phase 2B-6
 * development - see the design doc §15). No test assertion or ledger-code behavior changes between
 * the two modes - only how the target database's connection info is obtained.
 */
final class PostgresTestTarget implements AutoCloseable {

    private final String jdbcUrl;
    private final String username;
    private final String password;
    private final PostgreSQLContainer<?> ownedContainer;

    private PostgresTestTarget(String jdbcUrl, String username, String password, PostgreSQLContainer<?> ownedContainer) {
        this.jdbcUrl = jdbcUrl;
        this.username = username;
        this.password = password;
        this.ownedContainer = ownedContainer;
    }

    static PostgresTestTarget start() {
        String externalUrl = System.getProperty("pgtest.jdbcUrl");
        String externalUsername = System.getProperty("pgtest.username");
        String externalPassword = System.getProperty("pgtest.password");
        if (externalUrl != null && externalUsername != null && externalPassword != null) {
            return new PostgresTestTarget(externalUrl, externalUsername, externalPassword, null);
        }
        PostgreSQLContainer<?> container = new PostgreSQLContainer<>("postgres:16-alpine");
        container.start();
        return new PostgresTestTarget(container.getJdbcUrl(), container.getUsername(), container.getPassword(), container);
    }

    String getJdbcUrl() {
        return jdbcUrl;
    }

    String getUsername() {
        return username;
    }

    String getPassword() {
        return password;
    }

    @Override
    public void close() {
        if (ownedContainer != null) {
            ownedContainer.stop();
        }
        // An external target is owned and torn down by whoever started it - never by this class.
    }
}
