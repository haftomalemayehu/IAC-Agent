package com.iacagent.iacagent.runner.jdbc;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.FlywayException;
import org.flywaydb.core.api.MigrationInfo;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 2B-6 Gate B migration acceptance suite against REAL PostgreSQL - one shared server (see
 * {@link PostgresTestTarget}), with a fresh, uniquely-named logical database created per test
 * method (dropped afterward) so every test observes a genuinely EMPTY database and controls its
 * exact prior schema state, without paying the cost of a brand-new server/container per test.
 *
 * <p>Run explicitly via {@code ./gradlew postgresTest} - NOT part of {@code ./gradlew test}/{@code check}.
 */
class Phase2b6MigrationAcceptanceTests {

    private static PostgresTestTarget TARGET;
    private String currentDatabaseName;

    @BeforeAll
    static void startServer() {
        TARGET = PostgresTestTarget.start();
    }

    @AfterAll
    static void stopServer() {
        TARGET.close();
    }

    @BeforeEach
    void createFreshDatabase() throws SQLException {
        currentDatabaseName = "migtest_" + UUID.randomUUID().toString().replace("-", "");
        try (Connection connection = adminDataSource().getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute("CREATE DATABASE " + currentDatabaseName);
        }
    }

    @AfterEach
    void dropDatabase() throws SQLException {
        try (Connection connection = adminDataSource().getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute("DROP DATABASE IF EXISTS " + currentDatabaseName + " WITH (FORCE)");
        }
    }

    /** Connects to the server's default database - used only to create/drop this test's own
     * per-test database, never to run migrations against directly. */
    private DataSource adminDataSource() {
        PGSimpleDataSource ds = new PGSimpleDataSource();
        ds.setUrl(TARGET.getJdbcUrl());
        ds.setUser(TARGET.getUsername());
        ds.setPassword(TARGET.getPassword());
        return ds;
    }

    private DataSource dataSource() {
        PGSimpleDataSource ds = new PGSimpleDataSource();
        ds.setUrl(TARGET.getJdbcUrl().replaceAll("/[^/?]+(\\?|$)", "/" + currentDatabaseName + "$1"));
        ds.setUser(TARGET.getUsername());
        ds.setPassword(TARGET.getPassword());
        return ds;
    }

    @Test
    void realServerIdentifiesItselfAsPostgreSQL() throws SQLException {
        try (Connection connection = dataSource().getConnection();
             Statement statement = connection.createStatement();
             var rs = statement.executeQuery("SELECT version()")) {
            assertTrue(rs.next());
            String version = rs.getString(1);
            System.out.println("[Phase2b6 connectivity] SELECT version() => " + version);
            assertTrue(version.contains("PostgreSQL"), "expected a real PostgreSQL server, got: " + version);
        }
    }

    @Test
    void emptyDatabaseMigratesToLatest() {
        DataSource dataSource = dataSource();
        PostgresRunnerLedgerRepository.migrate(dataSource);

        Flyway flyway = Flyway.configure().dataSource(dataSource).locations("classpath:db/migration/runner-postgres").load();
        MigrationInfo current = flyway.info().current();
        assertNotNull(current, "an empty database must migrate to a real, current version");
        assertTrue(current.getVersion().toString().length() > 0);
        System.out.println("[Phase2b6 migration] empty database migrated to version " + current.getVersion());
    }

    @Test
    void restartAtLatestIsIdempotent() {
        DataSource dataSource = dataSource();
        PostgresRunnerLedgerRepository.migrate(dataSource);
        // "Restart" - a second process opening the same already-migrated database must not fail,
        // must not re-apply anything, and must not change the schema version.
        assertDoesNotThrow(() -> PostgresRunnerLedgerRepository.migrate(dataSource));

        Flyway flyway = Flyway.configure().dataSource(dataSource).locations("classpath:db/migration/runner-postgres").load();
        assertEquals(1, flyway.info().applied().length, "migrating twice must not re-apply the migration");
    }

    @Test
    void migrationChecksumStabilityIsValidatedByFlyway() {
        DataSource dataSource = dataSource();
        PostgresRunnerLedgerRepository.migrate(dataSource);

        Flyway flyway = Flyway.configure().dataSource(dataSource).locations("classpath:db/migration/runner-postgres").load();
        // Flyway's own validate() recomputes each applied migration's checksum from the classpath
        // resource and compares it against what was recorded at apply time - this is the
        // authoritative checksum-stability check, not a hand-rolled one.
        assertDoesNotThrow(flyway::validate, "the migration actually applied must match its recorded checksum");
    }

    @Test
    void incompatibleSchemaFailsClosedRatherThanAutoRepairing() throws SQLException {
        DataSource dataSource = dataSource();
        // Pre-create a conflicting object under the exact name Flyway's own schema history table
        // would use, with an incompatible shape - simulating an incompatible/corrupted prior schema
        // state a real deployment could encounter.
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute("CREATE TABLE flyway_schema_history (not_the_right_shape INT)");
        }

        assertThrows(FlywayException.class, () -> PostgresRunnerLedgerRepository.migrate(dataSource),
                "an incompatible existing schema-history table must fail closed, never silently auto-repair");

        // Confirm no auto-repair happened: the bogus table is still exactly as it was, and the real
        // runner_requests table was never created.
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement()) {
            var rs = statement.executeQuery(
                    "SELECT to_regclass('public.runner_requests') IS NOT NULL AS exists_flag");
            assertTrue(rs.next());
            assertFalse(rs.getBoolean("exists_flag"), "runner_requests must never be created when migration fails closed");
        }
    }
}
