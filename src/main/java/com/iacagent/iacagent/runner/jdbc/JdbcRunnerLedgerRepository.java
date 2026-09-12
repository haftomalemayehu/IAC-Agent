package com.iacagent.iacagent.runner.jdbc;

import com.iacagent.iacagent.approval.ApprovalValidationReasonCode;
import com.iacagent.iacagent.runner.RunnerClaimOutcome;
import com.iacagent.iacagent.runner.RunnerClaimState;
import com.iacagent.iacagent.runner.RunnerEvidence;
import com.iacagent.iacagent.runner.RunnerLedgerPersistenceException;
import com.iacagent.iacagent.runner.RunnerLedgerRepository;
import com.iacagent.iacagent.runner.RunnerOperation;
import com.iacagent.iacagent.runner.RunnerReasonCode;
import com.iacagent.iacagent.runner.RunnerRequest;
import com.iacagent.iacagent.runner.RunnerState;
import org.flywaydb.core.Flyway;
import org.h2.jdbcx.JdbcConnectionPool;

import javax.sql.DataSource;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Phase 2B-2 durable {@link RunnerLedgerRepository} reference implementation - plain JDBC, the
 * same architectural pattern as {@code com.iacagent.iacagent.approval.jdbc.JdbcApprovalRepository}
 * (no ORM, no DI wiring, Flyway-versioned schema). Carries the SAME H2-is-a-milestone-backend
 * caveat: this is the Phase 2B-2 durable reference/acceptance backend, not a claim that H2
 * satisfies the production hard gates recorded in the Phase 2B-2 design doc (Gate A: approval
 * persistence needs real PostgreSQL integration/concurrency validation; Gate B: this ledger needs
 * the same before real execution authority exists).
 *
 * <p>The atomic claim ({@link #claim}) is a plain {@code INSERT}: the table's primary key on
 * {@code runner_request_id} is the actual atomicity primitive, exactly as
 * {@code JdbcApprovalRepository#create} relies on its own primary key for duplicate-id detection.
 * Exactly one concurrent {@code INSERT} for a given id can ever succeed, guaranteed by the
 * database regardless of how many callers race - no read-then-write window exists for the claim
 * decision itself. On a primary-key violation, a separate, non-transactional read classifies the
 * existing row (same fingerprint + COMPLETED -&gt; duplicate; same fingerprint + CLAIMED -&gt;
 * incomplete prior claim; different fingerprint -&gt; mismatch) purely to inform the caller - it does
 * not write anything, so a benign race in that classification (the row's state changing between
 * the failed insert and this read) cannot corrupt the ledger, only occasionally report a
 * marginally stale-but-still-safe reason to the loser of the race.
 */
public final class JdbcRunnerLedgerRepository implements RunnerLedgerRepository {

    private final DataSource dataSource;

    public JdbcRunnerLedgerRepository(DataSource dataSource) {
        if (dataSource == null) {
            throw new IllegalArgumentException("dataSource is required");
        }
        this.dataSource = dataSource;
    }

    /** Opens (creating and migrating if necessary) an H2 file-backed ledger under {@code databaseDirectory}. */
    public static JdbcRunnerLedgerRepository openH2FileBacked(Path databaseDirectory) {
        return new JdbcRunnerLedgerRepository(createMigratedH2FileBackedDataSource(databaseDirectory));
    }

    /** Package-visible so tests can wrap the raw DataSource (e.g. for fault injection). */
    static DataSource createMigratedH2FileBackedDataSource(Path databaseDirectory) {
        String url = "jdbc:h2:file:" + databaseDirectory.toAbsolutePath().resolve("runner-ledger")
                + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE";
        DataSource dataSource = JdbcConnectionPool.create(url, "sa", "");
        Flyway.configure()
                .dataSource(dataSource)
                .locations("classpath:db/migration/runner")
                .load()
                .migrate();
        return dataSource;
    }

    public void close() {
        if (dataSource instanceof JdbcConnectionPool pool) {
            pool.dispose();
        }
    }

    @Override
    public RunnerClaimOutcome claim(RunnerRequest request, Instant claimedAt) {
        String fingerprint = request.fingerprintSha256();
        try {
            insertClaim(request, fingerprint, claimedAt);
            return RunnerClaimOutcome.CLAIMED;
        } catch (SQLException e) {
            if (!"23505".equals(e.getSQLState())) {
                throw new RunnerLedgerPersistenceException("failed to claim runner request " + request.runnerRequestId(), e);
            }
            // fall through: id already exists, classify the existing row
        } catch (RuntimeException e) {
            // e.g. H2's JdbcConnectionPool#getConnection throws IllegalStateException (not
            // SQLException) once the pool has been disposed - a genuine infrastructure failure,
            // not a domain outcome, so it must fail closed exactly like a SQLException would.
            throw new RunnerLedgerPersistenceException("failed to claim runner request " + request.runnerRequestId(), e);
        }
        Optional<ExistingClaim> existing = selectExistingClaim(request.runnerRequestId());
        if (existing.isEmpty()) {
            // The insert failed as a duplicate, but a fresh read finds nothing - an internal
            // inconsistency this repository cannot explain, treated as an infrastructure failure
            // rather than guessed at.
            throw new RunnerLedgerPersistenceException(
                    "claim reported a duplicate for " + request.runnerRequestId() + " but no row was found on re-read", null);
        }
        if (!existing.get().fingerprint().equals(fingerprint)) {
            return RunnerClaimOutcome.FINGERPRINT_MISMATCH;
        }
        return existing.get().claimState() == RunnerClaimState.COMPLETED
                ? RunnerClaimOutcome.DUPLICATE_SAME_FINGERPRINT
                : RunnerClaimOutcome.INCOMPLETE_PRIOR_CLAIM;
    }

    @Override
    public void recordTerminalEvidence(RunnerEvidence evidence) {
        String sql = """
                UPDATE runner_requests
                SET claim_state = 'COMPLETED',
                    runner_id = ?, runner_class = ?, runner_environment_scope = ?,
                    observed_plan_sha256 = ?, terraform_version_observed = ?, provider_lock_hash_observed = ?,
                    approval_validation_result = ?, final_state = ?, reason_codes = ?, completed_at = ?,
                    terraform_process_evidence = ?, terraform_init_evidence = ?, terraform_validate_evidence = ?,
                    terraform_provider_schema_evidence = ?,
                    version = version + 1, updated_at = ?
                WHERE runner_request_id = ? AND claim_state = 'CLAIMED'
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
            ps.setString(i++, TerraformProcessEvidenceJson.toJson(evidence.terraformProcessEvidence()));
            ps.setString(i++, TerraformInitEvidenceJson.toJson(evidence.terraformInitEvidence()));
            ps.setString(i++, TerraformValidateEvidenceJson.toJson(evidence.terraformValidateEvidence()));
            ps.setString(i++, TerraformProviderSchemaEvidenceJson.toJson(evidence.terraformProviderSchemaEvidence()));
            setInstant(ps, i++, evidence.completedAt());
            ps.setString(i, evidence.runnerRequestId());
            updated = ps.executeUpdate();
        } catch (SQLException | RuntimeException e) {
            // Covers both a genuine SQLException and e.g. H2's JdbcConnectionPool#getConnection
            // throwing IllegalStateException (not SQLException) once the pool has been disposed -
            // either way this is an infrastructure failure, not a domain outcome.
            throw new RunnerLedgerPersistenceException("failed to record terminal evidence for " + evidence.runnerRequestId(), e);
        }
        if (updated != 1) {
            throw new IllegalStateException(
                    "cannot record terminal evidence for an id that was not freshly claimed: " + evidence.runnerRequestId());
        }
    }

    @Override
    public Optional<RunnerEvidence> findHistoricalEvidence(String runnerRequestId) {
        String sql = "SELECT * FROM runner_requests WHERE runner_request_id = ? AND claim_state = 'COMPLETED'";
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, runnerRequestId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(mapEvidence(rs)) : Optional.empty();
            }
        } catch (SQLException | RuntimeException e) {
            throw new RunnerLedgerPersistenceException("failed to resolve historical evidence for " + runnerRequestId, e);
        }
    }

    private void insertClaim(RunnerRequest request, String fingerprint, Instant claimedAt) throws SQLException {
        String sql = """
                INSERT INTO runner_requests (
                    runner_request_id, request_fingerprint,
                    repository, commit_sha, environment, plan_artifact_id, plan_sha256,
                    terraform_version_expected, provider_lock_hash_expected, approval_id, requested_operation,
                    claim_state, started_at, version, created_at, updated_at
                ) VALUES (?,?, ?,?,?,?,?, ?,?,?,?, 'CLAIMED', ?, 0, ?, ?)
                """;
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
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
            setInstant(ps, i++, claimedAt);
            setInstant(ps, i++, claimedAt);
            setInstant(ps, i, claimedAt);
            ps.executeUpdate();
        }
        // SQLException (including a 23505 primary-key violation) propagates to claim(), which owns
        // the full classification: 23505 falls through to a read-based classification, anything
        // else becomes RunnerLedgerPersistenceException.
    }

    private record ExistingClaim(String fingerprint, RunnerClaimState claimState) {
    }

    private Optional<ExistingClaim> selectExistingClaim(String runnerRequestId) {
        String sql = "SELECT request_fingerprint, claim_state FROM runner_requests WHERE runner_request_id = ?";
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, runnerRequestId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return Optional.empty();
                }
                return Optional.of(new ExistingClaim(rs.getString("request_fingerprint"), RunnerClaimState.valueOf(rs.getString("claim_state"))));
            }
        } catch (SQLException | RuntimeException e) {
            throw new RunnerLedgerPersistenceException("failed to classify existing claim for " + runnerRequestId, e);
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
                : new java.util.LinkedHashSet<>(Arrays.asList(scopeRaw.split(",")));
        String approvalResultRaw = rs.getString("approval_validation_result");
        String finalStateRaw = rs.getString("final_state");

        return new RunnerEvidence(
                rs.getString("runner_request_id"),
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
                readInstant(rs, "started_at"),
                readInstant(rs, "completed_at"),
                TerraformProcessEvidenceJson.fromJson(rs.getString("terraform_process_evidence")),
                TerraformInitEvidenceJson.fromJson(TerraformInitEvidenceJson.parseTree(rs.getString("terraform_init_evidence"))),
                TerraformValidateEvidenceJson.fromJson(rs.getString("terraform_validate_evidence")),
                TerraformProviderSchemaEvidenceJson.fromJson(rs.getString("terraform_provider_schema_evidence"))
        );
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
            ps.setNull(index, java.sql.Types.TIMESTAMP_WITH_TIMEZONE);
        } else {
            ps.setObject(index, OffsetDateTime.ofInstant(instant, ZoneOffset.UTC));
        }
    }
}
