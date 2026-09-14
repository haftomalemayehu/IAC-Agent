package com.iacagent.iacagent.runner.jdbc;

import com.iacagent.iacagent.approval.ApprovalValidationReasonCode;
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
import org.flywaydb.core.Flyway;
import org.postgresql.ds.PGSimpleDataSource;
import org.postgresql.util.PGobject;

import javax.sql.DataSource;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Types;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Phase 2B-6 production {@link RunnerLedgerRepository}: the ONLY implementation in this codebase
 * backed by a real, externally durable PostgreSQL database rather than H2/in-memory. Targets Gate B
 * exclusively - it does not touch, widen, or claim to close the approval-persistence gate (Gate A),
 * even though {@code com.iacagent.iacagent.approval.jdbc.JdbcApprovalRepository} could in principle
 * be pointed at PostgreSQL the same way.
 *
 * <p><b>Atomic claim.</b> {@link #claim} issues a single {@code INSERT ... ON CONFLICT (request_id)
 * DO NOTHING} - the row's primary key is the actual, database-enforced concurrency boundary; no
 * read-then-write window exists for the claim decision itself, and no JVM-level synchronization is
 * involved. Exactly one concurrent caller for a given {@code request_id} ever inserts the row;
 * every other caller observes zero rows affected and classifies the row a SEPARATE, read-only
 * {@code SELECT} then describes (not decides) - a benign race in that classification cannot corrupt
 * the ledger, since the classification statement never writes anything.
 *
 * <p><b>Ambiguous outcome.</b> If the {@code INSERT} statement itself throws once it has already
 * been transmitted to the server (e.g. the connection breaks while awaiting the commit
 * acknowledgment), this repository cannot know whether the row was actually created. Per the Phase
 * 2B-6 authorization, this is reported as {@link RunnerClaimOutcome#AMBIGUOUS} - a first-class
 * domain outcome, not folded into either {@code CLAIMED} or a thrown
 * {@link RunnerLedgerPersistenceException} - so the caller ({@code ControlledRunner}) blocks rather
 * than guessing. No retry is attempted inside this method: a later resubmission of the same
 * {@code runnerRequestId} is what safely resolves the ambiguity, because the SAME
 * {@code INSERT ... ON CONFLICT} logic will then observe whichever outcome the database actually
 * settled on. A connection failure that occurs BEFORE the statement is ever sent (e.g. pool
 * exhaustion, host unreachable) is unambiguous - nothing was transmitted - and is reported as a
 * plain {@link RunnerLedgerPersistenceException} instead.
 *
 * <p><b>Guarded completion.</b> {@link #recordTerminalEvidence} issues a single guarded
 * {@code UPDATE ... WHERE request_id = ? AND fingerprint = ? AND state = 'CLAIMED'}. The fingerprint
 * predicate is not redundant with the caller's own claim-time check: it is recomputed here from the
 * evidence's own identity fields (the exact nine semantic fields
 * {@link RunnerRequest#fingerprintSha256()} hashes) using the same algorithm, so a discipline
 * violation elsewhere (completing a row with evidence for a DIFFERENT logical request than the one
 * that was claimed under this id) is caught here too, not only trusted from the caller. Zero rows
 * affected is never treated as success - {@link IllegalStateException} is thrown, matching
 * {@link RunnerLedgerRepository#recordTerminalEvidence}'s documented contract.
 *
 * <p><b>Why completion has no AMBIGUOUS outcome, deliberately.</b> Unlike {@link #claim}, an
 * ambiguous {@code UPDATE} here cannot cause a double execution: the row either genuinely committed
 * to {@code COMPLETED} (a later replay observes {@code DUPLICATE_SAME_FINGERPRINT} - safe) or it
 * never did (the row stays {@code CLAIMED} forever, blocking all future attempts under this id as
 * {@code INCOMPLETE_PRIOR_CLAIM} until a human intervenes - also safe, if inconvenient). Either way
 * no second execution can occur, so a plain thrown {@link RunnerLedgerPersistenceException} (which
 * {@code ControlledRunner} already treats as BLOCKED, never handing back an authoritative result)
 * is sufficient.
 *
 * <p><b>Immutability.</b> The database itself - not just this class's SQL - enforces that a
 * {@code COMPLETED} row can never be updated again and that identity/fingerprint/{@code claimed_at}
 * fields can never change after claim, via a {@code BEFORE UPDATE} trigger in the
 * {@code runner-postgres} Flyway migration. See {@code docs/phase-2b6-production-runner-ledger.md}.
 *
 * <p><b>Transaction/isolation model.</b> Every statement here runs under the connection pool's
 * default autocommit mode at PostgreSQL's default {@code READ COMMITTED} isolation - there is no
 * multi-statement transaction anywhere in this class (the claim's optional follow-up classification
 * {@code SELECT} is a separate, read-only, non-atomic-with-the-insert statement by design, since it
 * only describes an outcome the database has already settled). Correctness therefore rests entirely
 * on the primary key / {@code ON CONFLICT} semantics and the guarded {@code UPDATE}'s {@code WHERE}
 * clause, never on isolation level - {@code SERIALIZABLE} is neither used nor required.
 */
public final class PostgresRunnerLedgerRepository implements RunnerLedgerRepository {

    private static final String FLYWAY_LOCATION = "classpath:db/migration/runner-postgres";

    private final DataSource dataSource;
    private final RunnerLedgerObserver observer;

    public PostgresRunnerLedgerRepository(DataSource dataSource, RunnerLedgerObserver observer) {
        if (dataSource == null) {
            throw new IllegalArgumentException("dataSource is required");
        }
        this.dataSource = dataSource;
        this.observer = observer == null ? RunnerLedgerObserver.noOp() : observer;
    }

    public PostgresRunnerLedgerRepository(DataSource dataSource) {
        this(dataSource, RunnerLedgerObserver.noOp());
    }

    /** The sole production entry point: builds a bounded HikariCP pool per {@code config}, migrates
     * the schema, and returns a ready repository logging sanitized events via SLF4J. Never falls
     * back to any other persistence - a configuration or connectivity problem throws instead. */
    public static PostgresRunnerLedgerRepository forProduction(PostgresRunnerLedgerConfig config) {
        return forProduction(config, new Slf4jRunnerLedgerObserver());
    }

    public static PostgresRunnerLedgerRepository forProduction(PostgresRunnerLedgerConfig config, RunnerLedgerObserver observer) {
        if (config == null) {
            throw new IllegalArgumentException("config is required");
        }
        DataSource pooled = createPooledDataSource(config);
        migrate(pooled);
        return new PostgresRunnerLedgerRepository(pooled, observer);
    }

    /** Test-only entry point: the caller supplies its own already-reachable {@link DataSource} (a
     * Testcontainers-backed one in practice) and this method runs the exact same production
     * migration set against it before returning a ready repository. */
    public static PostgresRunnerLedgerRepository forTests(DataSource dataSource, RunnerLedgerObserver observer) {
        migrate(dataSource);
        return new PostgresRunnerLedgerRepository(dataSource, observer);
    }

    /** Runs the {@code runner-postgres} Flyway migration set against {@code dataSource}. Exposed
     * separately so acceptance tests can exercise migration behavior (empty database, restart at
     * latest, checksum stability, incompatible schema) directly. Never auto-repairs a failed/
     * mismatched migration state - a genuine failure here throws and this method makes no attempt
     * to recover automatically. */
    public static void migrate(DataSource dataSource) {
        Flyway.configure()
                .dataSource(dataSource)
                .locations(FLYWAY_LOCATION)
                .load()
                .migrate();
    }

    private static DataSource createPooledDataSource(PostgresRunnerLedgerConfig config) {
        PGSimpleDataSource pg = new PGSimpleDataSource();
        pg.setUrl(config.jdbcUrl());
        pg.setSslMode(config.tlsMode().jdbcSslMode());

        // Wraps pg so that every NEW physical connection HikariCP opens re-resolves the credential
        // via config.credentialSource().password() at that moment, rather than capturing it once
        // into a cached String field the way HikariConfig#setPassword would - see
        // RunnerLedgerCredentialSource's javadoc for why this matters.
        DataSource credentialResolvingDataSource = new CredentialResolvingDataSource(pg, config.username(), config.credentialSource());

        HikariConfig hikariConfig = new HikariConfig();
        hikariConfig.setDataSource(credentialResolvingDataSource);
        hikariConfig.setPoolName("runner-ledger-postgres");
        hikariConfig.setMinimumIdle(config.minPoolSize());
        hikariConfig.setMaximumPoolSize(config.maxPoolSize());
        hikariConfig.setConnectionTimeout(config.connectionTimeoutMillis());
        hikariConfig.setValidationTimeout(Math.min(config.connectionTimeoutMillis(), 5_000));
        // Bounds every statement this repository issues at the session level - "a stuck database
        // must fail closed rather than hold execution authority indefinitely."
        hikariConfig.setConnectionInitSql("SET statement_timeout = " + config.statementTimeoutMillis());
        return new HikariDataSource(hikariConfig);
    }

    @Override
    public RunnerClaimOutcome claim(RunnerRequest request, Instant claimedAt) {
        String fingerprint = request.fingerprintSha256();
        String requestId = request.runnerRequestId();
        Connection connection;
        try {
            connection = dataSource.getConnection();
        } catch (SQLException | RuntimeException e) {
            observer.onEvent(new RunnerLedgerEvent(RunnerLedgerEventType.DATABASE_UNAVAILABLE, requestId, Instant.now()));
            throw new RunnerLedgerPersistenceException("failed to obtain a database connection to claim " + requestId, e);
        }
        try {
            int inserted;
            try {
                inserted = insertClaim(connection, request, fingerprint, claimedAt);
            } catch (SQLException e) {
                // The statement was transmitted; its outcome is not knowable from this exception
                // alone. See class javadoc "Ambiguous outcome."
                observer.onEvent(new RunnerLedgerEvent(RunnerLedgerEventType.AMBIGUOUS_RESULT, requestId, Instant.now()));
                return RunnerClaimOutcome.AMBIGUOUS;
            }
            if (inserted == 1) {
                observer.onEvent(new RunnerLedgerEvent(RunnerLedgerEventType.CLAIM_SUCCESS, requestId, Instant.now()));
                return RunnerClaimOutcome.CLAIMED;
            }
            // ON CONFLICT DO NOTHING resolved to zero rows: the database has ALREADY settled this
            // id's ownership. This read-only classification does not participate in that decision.
            ExistingClaim existing;
            try {
                existing = selectExistingClaim(connection, requestId);
            } catch (SQLException e) {
                observer.onEvent(new RunnerLedgerEvent(RunnerLedgerEventType.DATABASE_UNAVAILABLE, requestId, Instant.now()));
                throw new RunnerLedgerPersistenceException("failed to classify existing runner request row " + requestId, e);
            }
            if (existing == null) {
                throw new RunnerLedgerPersistenceException(
                        "claim reported a conflict for " + requestId + " but no row was found on re-read", null);
            }
            if (!existing.fingerprint().equals(fingerprint)) {
                observer.onEvent(new RunnerLedgerEvent(RunnerLedgerEventType.FINGERPRINT_MISMATCH, requestId, Instant.now()));
                return RunnerClaimOutcome.FINGERPRINT_MISMATCH;
            }
            if ("COMPLETED".equals(existing.state())) {
                observer.onEvent(new RunnerLedgerEvent(RunnerLedgerEventType.DUPLICATE, requestId, Instant.now()));
                return RunnerClaimOutcome.DUPLICATE_SAME_FINGERPRINT;
            }
            observer.onEvent(new RunnerLedgerEvent(RunnerLedgerEventType.INCOMPLETE_PRIOR_CLAIM, requestId, Instant.now()));
            return RunnerClaimOutcome.INCOMPLETE_PRIOR_CLAIM;
        } finally {
            closeQuietly(connection);
        }
    }

    @Override
    public void recordTerminalEvidence(RunnerEvidence evidence) {
        String fingerprint = reconstructFingerprint(evidence);
        String sql = """
                UPDATE runner_requests
                SET state = 'COMPLETED',
                    runner_id = ?, runner_class = ?, runner_environment_scope = ?,
                    observed_plan_sha256 = ?, terraform_version_observed = ?, provider_lock_hash_observed = ?,
                    approval_validation_result = ?, final_state = ?, reason_codes = ?, completed_at = ?,
                    terraform_process_evidence = ?, terraform_init_evidence = ?, terraform_validate_evidence = ?,
                    terraform_provider_schema_evidence = ?, terraform_plan_evidence = ?,
                    updated_at = now()
                WHERE request_id = ? AND fingerprint = ? AND state = 'CLAIMED'
                """;
        int updated;
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            int i = 1;
            ps.setString(i++, evidence.runnerId());
            ps.setString(i++, evidence.runnerClass());
            ps.setString(i++, joinOrNull(evidence.runnerEnvironmentScope()));
            ps.setString(i++, evidence.observedPlanSha256());
            ps.setString(i++, evidence.terraformVersionObserved());
            ps.setString(i++, evidence.providerLockHashObserved());
            ps.setString(i++, evidence.approvalValidationResult() == null ? null : evidence.approvalValidationResult().name());
            ps.setString(i++, evidence.finalState() == null ? null : evidence.finalState().name());
            ps.setString(i++, joinReasonCodesOrNull(evidence.reasonCodes()));
            setInstant(ps, i++, evidence.completedAt());
            setJsonb(ps, i++, TerraformProcessEvidenceJson.toJson(evidence.terraformProcessEvidence()));
            setJsonb(ps, i++, TerraformInitEvidenceJson.toJson(evidence.terraformInitEvidence()));
            setJsonb(ps, i++, TerraformValidateEvidenceJson.toJson(evidence.terraformValidateEvidence()));
            setJsonb(ps, i++, TerraformProviderSchemaEvidenceJson.toJson(evidence.terraformProviderSchemaEvidence()));
            setJsonb(ps, i++, TerraformPlanEvidenceJson.toJson(evidence.terraformPlanEvidence()));
            ps.setString(i++, evidence.runnerRequestId());
            ps.setString(i, fingerprint);
            updated = ps.executeUpdate();
        } catch (SQLException | RuntimeException e) {
            observer.onEvent(new RunnerLedgerEvent(RunnerLedgerEventType.DATABASE_UNAVAILABLE, evidence.runnerRequestId(), Instant.now()));
            // Deliberately NOT an AMBIGUOUS domain outcome - see class javadoc "Why completion has
            // no AMBIGUOUS outcome, deliberately." A thrown infrastructure failure is sufficient
            // because ControlledRunner already treats it as BLOCKED and never hands back an
            // authoritative result, and no second execution can occur either way.
            throw new RunnerLedgerPersistenceException("failed to record terminal evidence for " + evidence.runnerRequestId(), e);
        }
        if (updated != 1) {
            throw new IllegalStateException(
                    "cannot record terminal evidence for an id that was not freshly claimed with a matching fingerprint: " + evidence.runnerRequestId());
        }
        observer.onEvent(new RunnerLedgerEvent(RunnerLedgerEventType.COMPLETION, evidence.runnerRequestId(), Instant.now()));
    }

    @Override
    public Optional<RunnerEvidence> findHistoricalEvidence(String runnerRequestId) {
        String sql = "SELECT * FROM runner_requests WHERE request_id = ? AND state = 'COMPLETED'";
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, runnerRequestId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(mapEvidence(rs)) : Optional.empty();
            }
        } catch (SQLException | RuntimeException e) {
            // Never converted into Optional.empty() - a database error must never be interpreted
            // as "no previous claim exists."
            observer.onEvent(new RunnerLedgerEvent(RunnerLedgerEventType.DATABASE_UNAVAILABLE, runnerRequestId, Instant.now()));
            throw new RunnerLedgerPersistenceException("failed to resolve historical evidence for " + runnerRequestId, e);
        }
    }

    /** Recomputes the fingerprint that MUST have been stored at claim time from the evidence's own
     * identity fields - the same nine semantic fields {@link RunnerRequest#fingerprintSha256()}
     * hashes, just named with an "Expected"/"Observed" split on {@link RunnerEvidence}. Never a
     * second, competing fingerprint definition - this is the identical algorithm, applied to values
     * that (for the fields it uses) are always the original request's own claim. */
    private static String reconstructFingerprint(RunnerEvidence evidence) {
        RunnerRequest reconstructed = new RunnerRequest(
                evidence.runnerRequestId(), evidence.repository(), evidence.commitSha(), evidence.environment(),
                evidence.planArtifactId(), evidence.expectedPlanSha256(), evidence.terraformVersionExpected(),
                evidence.providerLockHashExpected(), evidence.approvalId(), evidence.operation());
        return reconstructed.fingerprintSha256();
    }

    private int insertClaim(Connection connection, RunnerRequest request, String fingerprint, Instant claimedAt) throws SQLException {
        String sql = """
                INSERT INTO runner_requests (
                    request_id, fingerprint,
                    repository, commit_sha, environment, plan_artifact_id, plan_sha256,
                    terraform_version_expected, provider_lock_hash_expected, approval_id, requested_operation,
                    state, claimed_at, created_at, updated_at
                ) VALUES (?,?, ?,?,?,?,?, ?,?,?,?, 'CLAIMED', ?, now(), now())
                ON CONFLICT (request_id) DO NOTHING
                """;
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            int i = 1;
            ps.setString(i++, request.runnerRequestId());
            ps.setString(i++, fingerprint);
            ps.setString(i++, request.repository());
            ps.setString(i++, request.commitSha());
            ps.setString(i++, request.environment());
            ps.setString(i++, request.planArtifactId());
            ps.setString(i++, request.planSha256());
            ps.setString(i++, request.terraformVersion());
            ps.setString(i++, request.providerLockHash());
            ps.setString(i++, request.approvalId());
            ps.setString(i++, request.requestedOperation().name());
            setInstant(ps, i, claimedAt);
            return ps.executeUpdate();
        }
    }

    private record ExistingClaim(String fingerprint, String state) {
    }

    private ExistingClaim selectExistingClaim(Connection connection, String requestId) throws SQLException {
        String sql = "SELECT fingerprint, state FROM runner_requests WHERE request_id = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, requestId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? new ExistingClaim(rs.getString("fingerprint"), rs.getString("state")) : null;
            }
        }
    }

    private RunnerEvidence mapEvidence(ResultSet rs) throws SQLException {
        String reasonCodesRaw = rs.getString("reason_codes");
        List<RunnerReasonCode> reasonCodes = reasonCodesRaw == null || reasonCodesRaw.isBlank()
                ? List.of()
                : Arrays.stream(reasonCodesRaw.split(",")).map(RunnerReasonCode::valueOf).collect(Collectors.toList());
        String scopeRaw = rs.getString("runner_environment_scope");
        Set<String> scope = scopeRaw == null || scopeRaw.isBlank()
                ? Set.of()
                : new LinkedHashSet<>(Arrays.asList(scopeRaw.split(",")));
        String approvalResultRaw = rs.getString("approval_validation_result");
        String finalStateRaw = rs.getString("final_state");

        return new RunnerEvidence(
                rs.getString("request_id"),
                rs.getString("runner_id"),
                rs.getString("runner_class"),
                scope,
                RunnerOperation.valueOf(rs.getString("requested_operation")),
                rs.getString("repository"),
                rs.getString("commit_sha"),
                rs.getString("environment"),
                rs.getString("plan_artifact_id"),
                rs.getString("plan_sha256"),
                rs.getString("observed_plan_sha256"),
                rs.getString("terraform_version_expected"),
                rs.getString("terraform_version_observed"),
                rs.getString("provider_lock_hash_expected"),
                rs.getString("provider_lock_hash_observed"),
                rs.getString("approval_id"),
                approvalResultRaw == null ? null : ApprovalValidationReasonCode.valueOf(approvalResultRaw),
                finalStateRaw == null ? null : RunnerState.valueOf(finalStateRaw),
                reasonCodes,
                readInstant(rs, "claimed_at"),
                readInstant(rs, "completed_at"),
                TerraformProcessEvidenceJson.fromJson(rs.getString("terraform_process_evidence")),
                TerraformInitEvidenceJson.fromJson(TerraformInitEvidenceJson.parseTree(rs.getString("terraform_init_evidence"))),
                TerraformValidateEvidenceJson.fromJson(rs.getString("terraform_validate_evidence")),
                TerraformProviderSchemaEvidenceJson.fromJson(rs.getString("terraform_provider_schema_evidence")),
                TerraformPlanEvidenceJson.fromJson(rs.getString("terraform_plan_evidence"))
        );
    }

    private static void setJsonb(PreparedStatement ps, int index, String json) throws SQLException {
        if (json == null) {
            ps.setNull(index, Types.OTHER);
            return;
        }
        PGobject jsonb = new PGobject();
        jsonb.setType("jsonb");
        jsonb.setValue(json);
        ps.setObject(index, jsonb);
    }

    private static String joinOrNull(Set<String> values) {
        return values == null || values.isEmpty() ? null : String.join(",", values);
    }

    private static String joinReasonCodesOrNull(List<RunnerReasonCode> values) {
        if (values == null || values.isEmpty()) {
            return null;
        }
        List<String> names = new ArrayList<>();
        for (RunnerReasonCode code : values) {
            names.add(code.name());
        }
        return String.join(",", names);
    }

    private static Instant readInstant(ResultSet rs, String column) throws SQLException {
        OffsetDateTime value = rs.getObject(column, OffsetDateTime.class);
        return value == null ? null : value.toInstant();
    }

    private static void setInstant(PreparedStatement ps, int index, Instant instant) throws SQLException {
        if (instant == null) {
            ps.setNull(index, Types.TIMESTAMP_WITH_TIMEZONE);
        } else {
            ps.setObject(index, OffsetDateTime.ofInstant(instant, ZoneOffset.UTC));
        }
    }

    private static void closeQuietly(Connection connection) {
        try {
            connection.close();
        } catch (SQLException ignored) {
            // returning the connection to the pool failed - nothing further to do; the pool's own
            // validation will evict it on next borrow if it is genuinely broken.
        }
    }

    /** Delegates every {@link DataSource} method to {@code delegate} except {@link #getConnection()},
     * which re-resolves the credential from {@code credentialSource} on every call - i.e. every time
     * HikariCP opens a new physical connection - rather than capturing it once. See
     * {@link RunnerLedgerCredentialSource}'s javadoc. */
    private static final class CredentialResolvingDataSource implements DataSource {
        private final PGSimpleDataSource delegate;
        private final String username;
        private final RunnerLedgerCredentialSource credentialSource;

        CredentialResolvingDataSource(PGSimpleDataSource delegate, String username, RunnerLedgerCredentialSource credentialSource) {
            this.delegate = delegate;
            this.username = username;
            this.credentialSource = credentialSource;
        }

        @Override
        public Connection getConnection() throws SQLException {
            return delegate.getConnection(username, credentialSource.password());
        }

        @Override
        public Connection getConnection(String username, String password) throws SQLException {
            return delegate.getConnection(username, password);
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
            return delegate.getParentLogger();
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
