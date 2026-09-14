package com.iacagent.iacagent.runner.jdbc;

import com.iacagent.iacagent.runner.RunnerClaimOutcome;
import com.iacagent.iacagent.runner.RunnerEvidence;
import com.iacagent.iacagent.runner.RunnerLedgerPersistenceException;
import com.iacagent.iacagent.runner.RunnerLedgerRepository;
import com.iacagent.iacagent.runner.RunnerOperation;
import com.iacagent.iacagent.runner.RunnerReasonCode;
import com.iacagent.iacagent.runner.RunnerRequest;
import com.iacagent.iacagent.runner.RunnerState;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;

import javax.sql.DataSource;
import java.io.PrintWriter;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 2B-6 Gate B acceptance/concurrency suite against REAL PostgreSQL (Testcontainers) - this,
 * not the H2-backed unit suite, is the actual closure evidence for Gate B. One container is shared
 * across every test in this class (each test uses a fresh, randomly-suffixed {@code request_id}, so
 * no cross-test cleanup is needed); {@link Phase2b6MigrationAcceptanceTests} uses a fresh
 * container per test instead, since those tests specifically need to observe an empty database.
 *
 * <p>Run explicitly via {@code ./gradlew postgresTest} - NOT part of {@code ./gradlew test}/{@code check}.
 * See {@link PostgresTestTarget} for how the target PostgreSQL instance (Testcontainers-managed by
 * default, or an external already-running instance via {@code -Dpgtest.*} system properties) is
 * resolved.
 */
class Phase2b6PostgresAcceptanceTests {

    private static PostgresTestTarget TARGET;

    private static final String REPOSITORY = "owner/repository";
    private static final String COMMIT_SHA = "c".repeat(40);
    private static final String ENVIRONMENT = "nonprod";
    private static final String TERRAFORM_VERSION = "1.6.6";
    private static final String PROVIDER_LOCK_HASH = "sha256:lock-abc";

    @BeforeAll
    static void migrateOnce() {
        TARGET = PostgresTestTarget.start();
        PostgresRunnerLedgerRepository.migrate(freshDataSource());
    }

    @AfterAll
    static void tearDown() {
        TARGET.close();
    }

    private static DataSource freshDataSource() {
        PGSimpleDataSource ds = new PGSimpleDataSource();
        ds.setUrl(TARGET.getJdbcUrl());
        ds.setUser(TARGET.getUsername());
        ds.setPassword(TARGET.getPassword());
        return ds;
    }

    private static RunnerLedgerRepository freshRepository() {
        return new PostgresRunnerLedgerRepository(freshDataSource());
    }

    private static RunnerRequest requestFor(String requestId, String repository) {
        return new RunnerRequest(requestId, repository, COMMIT_SHA, ENVIRONMENT, "artifact-1", "plan-sha-1",
                TERRAFORM_VERSION, PROVIDER_LOCK_HASH, "approval-1", RunnerOperation.PREPARE_EXECUTION);
    }

    private static RunnerRequest requestFor(String requestId) {
        return requestFor(requestId, REPOSITORY);
    }

    private static RunnerEvidence evidenceFor(RunnerRequest request) {
        return new RunnerEvidence(
                request.runnerRequestId(), "runner-1", "test-runner", Set.of(ENVIRONMENT), request.requestedOperation(),
                request.repository(), request.commitSha(), request.environment(), request.planArtifactId(), request.planSha256(),
                request.planSha256(), request.terraformVersion(), request.terraformVersion(), request.providerLockHash(), request.providerLockHash(),
                request.approvalId(), null, RunnerState.READY_FOR_FUTURE_EXECUTION, List.of(),
                Instant.now(), Instant.now(), null);
    }

    private static String freshId(String label) {
        return "req-" + label + "-" + UUID.randomUUID();
    }

    // ===================== Atomic claim under real contention =====================

    @Test
    void twoSimultaneousIdenticalClaimsExactlyOneWins() throws Exception {
        assertExactlyOneClaimWinsUnderContention(2);
    }

    @Test
    void tenSimultaneousIdenticalClaimsExactlyOneWins() throws Exception {
        assertExactlyOneClaimWinsUnderContention(10);
    }

    @Test
    void fiftySimultaneousIdenticalClaimsExactlyOneWins() throws Exception {
        assertExactlyOneClaimWinsUnderContention(50);
    }

    private void assertExactlyOneClaimWinsUnderContention(int concurrency) throws Exception {
        RunnerLedgerRepository repository = freshRepository();
        RunnerRequest request = requestFor(freshId("contend-" + concurrency));
        ExecutorService pool = Executors.newFixedThreadPool(concurrency);
        try {
            CountDownLatch ready = new CountDownLatch(concurrency);
            CountDownLatch go = new CountDownLatch(1);
            List<Future<RunnerClaimOutcome>> futures = new ArrayList<>();
            for (int i = 0; i < concurrency; i++) {
                // Each thread uses its OWN repository/DataSource instance - independent connections,
                // exactly as the authorization requires ("independent connections, repository
                // instances, threads/process-equivalent callers").
                RunnerLedgerRepository perCaller = freshRepository();
                futures.add(pool.submit(() -> {
                    ready.countDown();
                    go.await();
                    return perCaller.claim(request, Instant.now());
                }));
            }
            ready.await(30, TimeUnit.SECONDS);
            go.countDown();
            List<RunnerClaimOutcome> outcomes = new ArrayList<>();
            for (Future<RunnerClaimOutcome> f : futures) {
                outcomes.add(f.get(60, TimeUnit.SECONDS));
            }

            long claimed = outcomes.stream().filter(o -> o == RunnerClaimOutcome.CLAIMED).count();
            long incomplete = outcomes.stream().filter(o -> o == RunnerClaimOutcome.INCOMPLETE_PRIOR_CLAIM).count();
            long ambiguous = outcomes.stream().filter(o -> o == RunnerClaimOutcome.AMBIGUOUS).count();
            long mismatch = outcomes.stream().filter(o -> o == RunnerClaimOutcome.FINGERPRINT_MISMATCH).count();
            long duplicate = outcomes.stream().filter(o -> o == RunnerClaimOutcome.DUPLICATE_SAME_FINGERPRINT).count();
            System.out.println("[Phase2b6 contention " + concurrency + "-way] CLAIMED=" + claimed
                    + " INCOMPLETE_PRIOR_CLAIM=" + incomplete + " AMBIGUOUS=" + ambiguous
                    + " FINGERPRINT_MISMATCH=" + mismatch + " DUPLICATE_SAME_FINGERPRINT=" + duplicate
                    + " total=" + outcomes.size());
            assertEquals(1, claimed, "exactly one caller must establish the claim: " + outcomes);
            assertEquals(0, ambiguous, "a healthy database under contention alone must never produce AMBIGUOUS: " + outcomes);
            assertEquals(concurrency - 1, incomplete, "every other caller must deterministically observe the already-established state: " + outcomes);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void concurrentSameIdDifferentFingerprintsNoOverwrite() throws Exception {
        String id = freshId("diff-fp");
        RunnerRequest a = requestFor(id, "owner/repo-a");
        RunnerRequest b = requestFor(id, "owner/repo-b");
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            CountDownLatch go = new CountDownLatch(1);
            Future<RunnerClaimOutcome> fa = pool.submit(() -> {
                go.await();
                return freshRepository().claim(a, Instant.now());
            });
            Future<RunnerClaimOutcome> fb = pool.submit(() -> {
                go.await();
                return freshRepository().claim(b, Instant.now());
            });
            go.countDown();
            RunnerClaimOutcome oa = fa.get(30, TimeUnit.SECONDS);
            RunnerClaimOutcome ob = fb.get(30, TimeUnit.SECONDS);

            List<RunnerClaimOutcome> outcomes = List.of(oa, ob);
            System.out.println("[Phase2b6 fingerprint-conflict] a=" + oa + " b=" + ob);
            assertEquals(1, outcomes.stream().filter(o -> o == RunnerClaimOutcome.CLAIMED).count(), outcomes.toString());
            assertEquals(1, outcomes.stream().filter(o -> o == RunnerClaimOutcome.FINGERPRINT_MISMATCH).count(), outcomes.toString());
        } finally {
            pool.shutdownNow();
        }
    }

    // ===================== Restart durability =====================

    @Test
    void restartDurabilityIncompleteClaimIsObservedByANewInstance() {
        RunnerLedgerRepository instanceA = freshRepository();
        RunnerRequest request = requestFor(freshId("restart-incomplete"));
        assertEquals(RunnerClaimOutcome.CLAIMED, instanceA.claim(request, Instant.now()));
        // "A disappears" - instanceA is simply never touched again. instanceB uses a brand-new
        // repository object AND a brand-new DataSource/connection pool pointed at the same durable
        // database - nothing in-process is shared with instanceA.
        RunnerLedgerRepository instanceB = freshRepository();
        assertEquals(RunnerClaimOutcome.INCOMPLETE_PRIOR_CLAIM, instanceB.claim(request, Instant.now()));
    }

    @Test
    void restartDurabilityCompletedIsObservedByANewInstanceAndDuplicateStaysBlocked() {
        RunnerLedgerRepository instanceA = freshRepository();
        RunnerRequest request = requestFor(freshId("restart-completed"));
        assertEquals(RunnerClaimOutcome.CLAIMED, instanceA.claim(request, Instant.now()));
        instanceA.recordTerminalEvidence(evidenceFor(request));

        RunnerLedgerRepository instanceB = freshRepository();
        assertEquals(RunnerClaimOutcome.DUPLICATE_SAME_FINGERPRINT, instanceB.claim(request, Instant.now()));
        assertTrue(instanceB.findHistoricalEvidence(request.runnerRequestId()).isPresent());
    }

    // ===================== Database outage behavior =====================

    private DataSource unreachableDataSource() {
        // Port 1 is a reserved, always-refused TCP port - connection refusal is immediate, so this
        // test never hangs waiting for a timeout.
        PGSimpleDataSource ds = new PGSimpleDataSource();
        ds.setUrl("jdbc:postgresql://127.0.0.1:1/nonexistent");
        ds.setUser("nobody");
        ds.setPassword("nothing");
        return ds;
    }

    @Test
    void databaseUnavailableBeforeClaimFailsClosed() {
        RunnerLedgerRepository repository = new PostgresRunnerLedgerRepository(unreachableDataSource());
        assertThrows(RunnerLedgerPersistenceException.class,
                () -> repository.claim(requestFor(freshId("outage-claim")), Instant.now()));
    }

    @Test
    void databaseUnavailableDuringReplayLookupFailsClosedNeverEmpty() {
        RunnerLedgerRepository repository = new PostgresRunnerLedgerRepository(unreachableDataSource());
        assertThrows(RunnerLedgerPersistenceException.class,
                () -> repository.findHistoricalEvidence("some-id"),
                "a database error must never be interpreted as 'no previous claim exists'");
    }

    @Test
    void connectionPoolExhaustionFailsClosedWithinABoundedTime() throws Exception {
        HikariConfig hikariConfig = new HikariConfig();
        hikariConfig.setJdbcUrl(TARGET.getJdbcUrl());
        hikariConfig.setUsername(TARGET.getUsername());
        hikariConfig.setPassword(TARGET.getPassword());
        hikariConfig.setMaximumPoolSize(1);
        hikariConfig.setConnectionTimeout(800);
        try (HikariDataSource boundedPool = new HikariDataSource(hikariConfig)) {
            RunnerLedgerRepository repository = new PostgresRunnerLedgerRepository(boundedPool);
            // Occupy the sole pooled connection directly, starving the repository's own attempt.
            try (Connection held = boundedPool.getConnection()) {
                long startedAt = System.nanoTime();
                assertThrows(RunnerLedgerPersistenceException.class,
                        () -> repository.claim(requestFor(freshId("pool-exhausted")), Instant.now()));
                long elapsedMillis = (System.nanoTime() - startedAt) / 1_000_000;
                assertTrue(elapsedMillis < 5_000,
                        "a stuck/exhausted pool must fail closed within its configured bound, not hang indefinitely - took " + elapsedMillis + "ms");
            }
        }
    }

    // ===================== Ambiguous commit outcome =====================

    @Test
    void ambiguousCommitOutcomeIsReportedAndAFreshRetryReconciles() {
        AckLossFaultInjectingDataSource faulty = new AckLossFaultInjectingDataSource(freshDataSource());
        RunnerLedgerRepository repository = new PostgresRunnerLedgerRepository(faulty);
        RunnerRequest request = requestFor(freshId("ambiguous"));

        faulty.armInsertAckLossOnce();
        RunnerClaimOutcome firstAttempt = repository.claim(request, Instant.now());
        assertEquals(RunnerClaimOutcome.AMBIGUOUS, firstAttempt,
                "a statement that reached the server but whose ack was lost must be reported as AMBIGUOUS, never CLAIMED and never a thrown failure");

        // Reconciliation: the exact same claim() logic, called fresh, must observe that the INSERT
        // actually committed during the ambiguous attempt.
        RunnerClaimOutcome retry = repository.claim(request, Instant.now());
        System.out.println("[Phase2b6 ambiguous-commit] firstAttempt=" + firstAttempt + " retry=" + retry);
        assertEquals(RunnerClaimOutcome.INCOMPLETE_PRIOR_CLAIM, retry,
                "a fresh resubmission must safely resolve the ambiguity by observing the row the ambiguous attempt actually created");
    }

    @Test
    void ambiguousCommitOutcomeNeverDoubleInsertsOnRetry() throws SQLException {
        AckLossFaultInjectingDataSource faulty = new AckLossFaultInjectingDataSource(freshDataSource());
        RunnerLedgerRepository repository = new PostgresRunnerLedgerRepository(faulty);
        RunnerRequest request = requestFor(freshId("ambiguous-no-dupe"));

        faulty.armInsertAckLossOnce();
        repository.claim(request, Instant.now());
        repository.claim(request, Instant.now());

        try (Connection connection = freshDataSource().getConnection();
             var statement = connection.prepareStatement("SELECT COUNT(*) AS n FROM runner_requests WHERE request_id = ?")) {
            statement.setString(1, request.runnerRequestId());
            try (var rs = statement.executeQuery()) {
                assertTrue(rs.next());
                assertEquals(1, rs.getInt("n"), "an ambiguous attempt followed by a retry must never produce two rows for the same id");
            }
        }
    }

    @Test
    void ambiguousCommitOutcomeStopsTheControlledRunnerPipelineEntirely(@org.junit.jupiter.api.io.TempDir java.nio.file.Path workspaceRoot) {
        // End-to-end, against the real database: the invocation that receives AMBIGUOUS must never
        // continue into any future execution authority within THIS SAME attempt - it must stop at
        // the claim step, never reach artifact resolution, identity checks beyond claim, or any
        // Terraform-adjacent work. A later, separate invocation is what safely reconciles (proven
        // above); this test proves the CURRENT attempt itself goes nowhere.
        AckLossFaultInjectingDataSource faulty = new AckLossFaultInjectingDataSource(freshDataSource());
        RunnerLedgerRepository ledger = new PostgresRunnerLedgerRepository(faulty);
        faulty.armInsertAckLossOnce();

        var markerArtifactStore = new com.iacagent.iacagent.runner.RunnerArtifactStore() {
            final java.util.concurrent.atomic.AtomicBoolean resolveCalled = new java.util.concurrent.atomic.AtomicBoolean(false);

            @Override
            public Optional<com.iacagent.iacagent.runner.StoredArtifact> resolve(String artifactId) {
                resolveCalled.set(true);
                return Optional.empty();
            }
        };
        var identity = new com.iacagent.iacagent.runner.RunnerIdentity("runner-1", "test-runner", Set.of(ENVIRONMENT), true);
        var runner = new com.iacagent.iacagent.runner.ControlledRunner(
                new com.iacagent.iacagent.runner.StaticRunnerIdentityProvider(identity),
                Set.of("test-runner"),
                new com.iacagent.iacagent.approval.RepositoryBackedApprovalProvider(new com.iacagent.iacagent.approval.InMemoryApprovalRepository()),
                markerArtifactStore,
                new com.iacagent.iacagent.runner.StaticRunnerToolchainContext(TERRAFORM_VERSION, PROVIDER_LOCK_HASH),
                new com.iacagent.iacagent.runner.RunnerWorkspaceManager(workspaceRoot),
                ledger,
                java.time.Clock.systemUTC()
        );

        RunnerEvidence evidence = runner.execute(requestFor(freshId("ambiguous-e2e")));

        System.out.println("[Phase2b6 ambiguous-e2e] finalState=" + evidence.finalState() + " reasonCodes=" + evidence.reasonCodes());
        assertEquals(RunnerState.BLOCKED, evidence.finalState());
        assertEquals(List.of(RunnerReasonCode.RUNNER_LEDGER_CLAIM_AMBIGUOUS), evidence.reasonCodes());
        assertFalse(markerArtifactStore.resolveCalled.get(),
                "an AMBIGUOUS claim outcome must stop the pipeline before artifact resolution - never proceed into any future execution authority");
    }

    // ===================== Completion guard / immutability (database-enforced) =====================

    @Test
    void completionRequiresExactlyOneMatchingRowAndRejectsARepeat() {
        RunnerLedgerRepository repository = freshRepository();
        RunnerRequest request = requestFor(freshId("completion-guard"));
        repository.claim(request, Instant.now());
        assertDoesNotThrow(() -> repository.recordTerminalEvidence(evidenceFor(request)));
        assertThrows(IllegalStateException.class, () -> repository.recordTerminalEvidence(evidenceFor(request)),
                "zero rows affected (already COMPLETED) must never be silently treated as success");
    }

    @Test
    void fingerprintMismatchInEvidenceCannotCompleteADifferentlyClaimedRow() {
        RunnerLedgerRepository repository = freshRepository();
        String id = freshId("fp-defense-in-depth");
        RunnerRequest legit = requestFor(id);
        assertEquals(RunnerClaimOutcome.CLAIMED, repository.claim(legit, Instant.now()));

        RunnerRequest impostor = requestFor(id, "attacker/repo");
        // The row IS in CLAIMED state (the state predicate alone would allow an update) but the
        // impostor's identity does not match what was actually claimed - the guarded UPDATE's
        // fingerprint predicate must reject this independently of the state predicate.
        assertThrows(IllegalStateException.class, () -> repository.recordTerminalEvidence(evidenceFor(impostor)));

        // The legitimately claimed row must still be completable normally afterward.
        assertDoesNotThrow(() -> repository.recordTerminalEvidence(evidenceFor(legit)));
    }

    @Test
    void completedRowCanNeverBeReopenedEvenAtRawSqlLevel() throws SQLException {
        RunnerLedgerRepository repository = freshRepository();
        RunnerRequest request = requestFor(freshId("trigger-guard-reopen"));
        repository.claim(request, Instant.now());
        repository.recordTerminalEvidence(evidenceFor(request));

        try (Connection connection = freshDataSource().getConnection();
             var statement = connection.createStatement()) {
            SQLException ex = assertThrows(SQLException.class, () -> statement.execute(
                    "UPDATE runner_requests SET state = 'CLAIMED' WHERE request_id = '" + request.runnerRequestId() + "'"));
            assertTrue(ex.getMessage().toLowerCase().contains("immutable"), ex.getMessage());
        }
    }

    @Test
    void identityFieldsCannotBeRewrittenAfterClaimEvenAtRawSqlLevel() throws SQLException {
        RunnerLedgerRepository repository = freshRepository();
        RunnerRequest request = requestFor(freshId("trigger-guard-identity"));
        repository.claim(request, Instant.now());

        try (Connection connection = freshDataSource().getConnection();
             var statement = connection.createStatement()) {
            SQLException ex = assertThrows(SQLException.class, () -> statement.execute(
                    "UPDATE runner_requests SET repository = 'attacker/repo' WHERE request_id = '" + request.runnerRequestId() + "'"));
            assertTrue(ex.getMessage().toLowerCase().contains("immutable"), ex.getMessage());
        }
    }

    // ===================== Evidence immutability =====================

    @Test
    void firstEvidenceRemainsAuthoritativeAndDuplicateReplayCannotReplaceIt() {
        RunnerLedgerRepository repository = freshRepository();
        RunnerRequest request = requestFor(freshId("evidence-immutable"));
        repository.claim(request, Instant.now());
        repository.recordTerminalEvidence(evidenceFor(request));

        assertEquals(RunnerClaimOutcome.DUPLICATE_SAME_FINGERPRINT, repository.claim(request, Instant.now()));
        Optional<RunnerEvidence> stored = repository.findHistoricalEvidence(request.runnerRequestId());
        assertTrue(stored.isPresent());
        assertEquals(RunnerState.READY_FOR_FUTURE_EXECUTION, stored.get().finalState());
    }

    // ===================== TLS posture =====================

    @Test
    void productionSslModeRequireRefusesThePlaintextTestContainer() {
        PostgresRunnerLedgerConfig config = new PostgresRunnerLedgerConfig(
                TARGET.getJdbcUrl(), TARGET.getUsername(), RunnerLedgerCredentialSource.forTests(TARGET.getPassword()),
                com.iacagent.iacagent.runner.jdbc.RunnerLedgerTlsMode.REQUIRE, 1, 2, 3_000, 5_000);
        // The Testcontainers image has no TLS listener - requesting sslmode=require against it must
        // fail the connection, proving the configured TLS posture actually reaches the driver
        // rather than being silently ignored.
        assertThrows(RuntimeException.class, () -> PostgresRunnerLedgerRepository.forProduction(config));
    }

    // ===================== Secret redaction against a real auth failure =====================

    @Test
    void wrongPasswordAuthFailureNeverLeaksThePasswordInAnyExceptionMessage() {
        String bogusPassword = "definitely-wrong-marker-pw-8f3c1a";
        PostgresRunnerLedgerConfig config = PostgresRunnerLedgerConfig.forTests(TARGET.getJdbcUrl(), TARGET.getUsername(), bogusPassword);

        Exception thrown = assertThrows(Exception.class, () -> PostgresRunnerLedgerRepository.forProduction(config));
        Throwable cursor = thrown;
        while (cursor != null) {
            assertFalse(String.valueOf(cursor.getMessage()).contains(bogusPassword),
                    "exception message must never contain the password: " + cursor.getMessage());
            cursor = cursor.getCause();
        }
        assertFalse(config.toString().contains(bogusPassword));
    }

    // ===================== Fault injection: simulate a lost commit acknowledgment =====================

    /**
     * Wraps a real {@link DataSource} so that, once armed, the NEXT {@code INSERT INTO
     * runner_requests} statement's {@code executeUpdate()} call is allowed to actually run
     * (committing for real, under autocommit, against the real database) and THEN throws - exactly
     * reproducing "the server committed the row but the client never received the acknowledgment."
     * This is a deterministic, real-database way to exercise
     * {@link PostgresRunnerLedgerRepository}'s handling of that exact scenario, which a live network
     * fault would only reproduce non-deterministically.
     */
    private static final class AckLossFaultInjectingDataSource implements DataSource {
        private final DataSource delegate;
        private final AtomicBoolean armed = new AtomicBoolean(false);

        AckLossFaultInjectingDataSource(DataSource delegate) {
            this.delegate = delegate;
        }

        void armInsertAckLossOnce() {
            armed.set(true);
        }

        @Override
        public Connection getConnection() throws SQLException {
            return wrap(delegate.getConnection());
        }

        @Override
        public Connection getConnection(String username, String password) throws SQLException {
            return wrap(delegate.getConnection(username, password));
        }

        private Connection wrap(Connection real) {
            InvocationHandler handler = (proxy, method, args) -> {
                if (method.getName().equals("prepareStatement") && args != null && args.length > 0 && args[0] instanceof String sql
                        && sql.contains("INSERT INTO runner_requests") && armed.get()) {
                    PreparedStatement realStatement = (PreparedStatement) invokeReal(method, real, args);
                    return wrapStatement(realStatement);
                }
                return invokeReal(method, real, args);
            };
            return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(), new Class<?>[]{Connection.class}, handler);
        }

        private PreparedStatement wrapStatement(PreparedStatement real) {
            InvocationHandler handler = (proxy, method, args) -> {
                if (method.getName().equals("executeUpdate")) {
                    invokeReal(method, real, args); // runs and commits for real (autocommit)
                    armed.set(false); // one-shot
                    throw new SQLException("simulated network failure after the statement executed - acknowledgment lost");
                }
                return invokeReal(method, real, args);
            };
            return (PreparedStatement) Proxy.newProxyInstance(
                    PreparedStatement.class.getClassLoader(), new Class<?>[]{PreparedStatement.class}, handler);
        }

        private static Object invokeReal(java.lang.reflect.Method method, Object target, Object[] args) throws Throwable {
            try {
                return method.invoke(target, args);
            } catch (InvocationTargetException e) {
                throw e.getCause();
            }
        }

        @Override
        public PrintWriter getLogWriter() throws SQLException {
            return delegate.getLogWriter();
        }

        @Override
        public void setLogWriter(PrintWriter out) throws SQLException {
            delegate.setLogWriter(out);
        }

        @Override
        public void setLoginTimeout(int seconds) throws SQLException {
            delegate.setLoginTimeout(seconds);
        }

        @Override
        public int getLoginTimeout() throws SQLException {
            return delegate.getLoginTimeout();
        }

        @Override
        public Logger getParentLogger() throws SQLFeatureNotSupportedException {
            throw new SQLFeatureNotSupportedException();
        }

        @Override
        public <T> T unwrap(Class<T> iface) throws SQLException {
            return delegate.unwrap(iface);
        }

        @Override
        public boolean isWrapperFor(Class<?> iface) throws SQLException {
            return delegate.isWrapperFor(iface);
        }
    }
}
