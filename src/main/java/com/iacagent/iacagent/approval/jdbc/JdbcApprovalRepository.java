package com.iacagent.iacagent.approval.jdbc;

import com.iacagent.iacagent.approval.ApprovalPersistenceException;
import com.iacagent.iacagent.approval.ApprovalProvenance;
import com.iacagent.iacagent.approval.ApprovalRecord;
import com.iacagent.iacagent.approval.ApprovalRepository;
import com.iacagent.iacagent.approval.ApprovalStatus;
import com.iacagent.iacagent.approval.SupersedingIssuanceResult;
import com.iacagent.iacagent.approval.TransitionOutcome;
import org.flywaydb.core.Flyway;
import org.h2.jdbcx.JdbcConnectionPool;

import javax.sql.DataSource;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

/**
 * Phase 2C-2 durable {@link ApprovalRepository} reference implementation: plain JDBC against a
 * relational store, with a Flyway-versioned schema and genuine transactional compare-and-set
 * lifecycle transitions. No ORM, no dependency-injection wiring, no Spring persistence
 * autoconfiguration - deliberately, so this repository is not accidentally reachable from any
 * unrelated part of the application. Nothing in the rest of the codebase constructs or depends on
 * this class.
 *
 * <p><b>H2 durability-gate status - read before treating this as production-ready:</b>
 * <pre>
 * H2 file-backed repository (this class, as configured by {@link #openH2FileBacked})
 *     = Phase 2C-2 durable reference / acceptance backend
 *
 * Before Phase 2A execution authority is granted to any component:
 *     = an external, production-grade durable datastore is required
 *     = real PostgreSQL integration and concurrency testing is a hard pre-execution gate
 * </pre>
 * This class proves the persistence abstraction, the migration mechanism, restart durability,
 * transactional atomicity, and the SQL-to-domain mapping - all of which are prerequisites for a
 * production store, and none of which change when the backend changes. It does NOT prove: multiple
 * application instances, cross-process concurrency at scale, database high availability,
 * backup/recovery, production authentication, TLS, database-level access controls, operational
 * durability practices, or real PostgreSQL locking semantics (H2's {@code MODE=PostgreSQL} affects
 * SQL dialect compatibility only, not lock manager behavior - H2's own locking is not proven
 * equivalent to Postgres's under contention). None of those are acceptable to leave unverified once
 * this repository sits behind actual {@code terraform apply} authority. Whoever authorizes Phase
 * 2A/2B runtime execution must not accept H2 file mode as that deployment's approval store without
 * first completing a real PostgreSQL integration/concurrency verification pass using the same
 * {@link ApprovalRepository} contract and the same schema/migration in {@code db/migration/approval}.
 *
 * <p>Portability groundwork already in place for that verification: the SQL used here (standard
 * {@code SELECT ... FOR UPDATE}, {@code UPDATE ... WHERE status = ? AND version = ?}, SQLSTATE
 * {@code 23505} for unique-constraint detection) is ANSI-standard and Postgres-compatible, and the
 * schema/migration is written without H2-specific extensions - but "written to be portable" and
 * "verified against the real target" are different claims, and only the first one has been made
 * good on as of this commit.
 *
 * <p><b>Fail-closed, never fail-open:</b> every method here either returns a genuine domain
 * outcome or throws {@link ApprovalPersistenceException}. There is no code path in this class, or
 * anywhere else in this package, that catches a persistence failure and substitutes an in-memory
 * fallback or a default "valid" result. If the durable store is unavailable, approval authority is
 * unavailable - callers must treat a thrown exception here as "cannot proceed."
 */
public final class JdbcApprovalRepository implements ApprovalRepository {

    private final DataSource dataSource;

    public JdbcApprovalRepository(DataSource dataSource) {
        if (dataSource == null) {
            throw new IllegalArgumentException("dataSource is required");
        }
        this.dataSource = dataSource;
    }

    /**
     * Opens (creating and migrating if necessary) an H2 file-backed database under
     * {@code databaseDirectory}. Data written here survives process restart - a fresh
     * {@code JdbcApprovalRepository} opened against the same directory, in a different call to
     * this method (a different connection pool, a different Java object graph entirely), resolves
     * the same records. See {@code Phase2c2Tests} for the restart-durability proof.
     */
    public static JdbcApprovalRepository openH2FileBacked(Path databaseDirectory) {
        return new JdbcApprovalRepository(createMigratedH2FileBackedDataSource(databaseDirectory));
    }

    /** Package-visible so tests can wrap the raw DataSource (e.g. for fault injection) without duplicating URL/migration setup. */
    static DataSource createMigratedH2FileBackedDataSource(Path databaseDirectory) {
        String url = "jdbc:h2:file:" + databaseDirectory.toAbsolutePath().resolve("approvals")
                + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE";
        DataSource dataSource = JdbcConnectionPool.create(url, "sa", "");
        runMigrations(dataSource);
        return dataSource;
    }

    private static void runMigrations(DataSource dataSource) {
        Flyway.configure()
                .dataSource(dataSource)
                .locations("classpath:db/migration/approval")
                .load()
                .migrate();
    }

    /** Closes the underlying connection pool, if this instance owns one that supports it. */
    public void close() {
        if (dataSource instanceof JdbcConnectionPool pool) {
            pool.dispose();
        }
    }

    @Override
    public ApprovalRecord create(ApprovalRecord record) {
        return withTransaction(connection -> {
            insertRecord(connection, record);
            return record;
        });
    }

    @Override
    public Optional<ApprovalRecord> find(String approvalId) {
        String sql = "SELECT * FROM approval_records WHERE approval_id = ?";
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, approvalId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(mapRow(rs)) : Optional.empty();
            }
        } catch (SQLException | RuntimeException e) {
            throw new ApprovalPersistenceException("failed to resolve approval " + approvalId, e);
        }
    }

    @Override
    public TransitionOutcome revoke(String approvalId, Instant revokedAt, String revokedBy, String reason) {
        return withTransaction(connection -> {
            Optional<CasSnapshot> snapshot = selectForUpdate(connection, approvalId);
            if (snapshot.isEmpty()) {
                return TransitionOutcome.NOT_FOUND;
            }
            if (snapshot.get().status() != ApprovalStatus.ACTIVE) {
                return TransitionOutcome.ALREADY_TRANSITIONED;
            }
            String sql = """
                    UPDATE approval_records
                    SET status = 'REVOKED', revoked_at = ?, revoked_by = ?, revocation_reason = ?,
                        version = version + 1, updated_at = ?
                    WHERE approval_id = ? AND status = 'ACTIVE' AND version = ?
                    """;
            try (PreparedStatement ps = connection.prepareStatement(sql)) {
                setInstant(ps, 1, revokedAt);
                ps.setString(2, revokedBy);
                ps.setString(3, reason);
                setInstant(ps, 4, revokedAt);
                ps.setString(5, approvalId);
                ps.setLong(6, snapshot.get().version());
                int updated = ps.executeUpdate();
                return updated == 1 ? TransitionOutcome.SUCCESS : TransitionOutcome.ALREADY_TRANSITIONED;
            }
        });
    }

    @Override
    public TransitionOutcome supersede(String approvalId, Instant supersededAt, String supersedingApprovalId, String supersedingPlanSha256) {
        return withTransaction(connection -> supersedeWithinTransaction(connection, approvalId, supersededAt, supersedingApprovalId, supersedingPlanSha256));
    }

    /**
     * All-or-nothing per approval SS4 of the Phase 2C-2 amendment review: on any outcome other than
     * SUCCESS, {@code newRecord} must not exist afterward and {@code priorApprovalId} must be
     * unchanged. This requires checking the prior approval's eligibility - under a row lock held
     * for the rest of the transaction - BEFORE inserting the new record, not after. An earlier
     * revision of this method inserted first and treated a failed supersede as a normal, non-
     * exceptional outcome, which left the new record committed (as a standalone ACTIVE approval)
     * even when its whole reason for being issued - superseding a specific prior approval - had
     * failed. That was a real defect, not a hypothetical one, and this method's structure now
     * makes it structurally impossible to repeat: nothing is written until eligibility is confirmed.
     */
    @Override
    public SupersedingIssuanceResult createAndSupersede(ApprovalRecord newRecord, String priorApprovalId, Instant supersededAt) {
        return withTransaction(connection -> {
            // SELECT ... FOR UPDATE takes and holds a row lock on the prior approval for the rest
            // of this transaction, so a concurrent createAndSupersede/revoke/supersede attempt on
            // the same prior row blocks here until this transaction commits or rolls back - by the
            // time it proceeds, it will see the now-committed (or rolled-back) status, never a
            // window in which two attempts both believe the prior is still ACTIVE.
            Optional<CasSnapshot> priorSnapshot = selectForUpdate(connection, priorApprovalId);
            if (priorSnapshot.isEmpty()) {
                return new SupersedingIssuanceResult(null, TransitionOutcome.NOT_FOUND);
            }
            if (priorSnapshot.get().status() != ApprovalStatus.ACTIVE) {
                return new SupersedingIssuanceResult(null, TransitionOutcome.ALREADY_TRANSITIONED);
            }

            insertRecord(connection, newRecord);
            int updated = executeSupersedeUpdate(connection, priorApprovalId, priorSnapshot.get().version(), supersededAt, newRecord.approvalId(), newRecord.planSha256());
            // `updated` can only fail to be 1 here if something else altered this row despite our
            // FOR UPDATE lock, which the lock itself is meant to prevent for the lifetime of this
            // transaction - treated conservatively (as ALREADY_TRANSITIONED, causing a full
            // rollback via the exception-free return path below) rather than assumed impossible.
            if (updated != 1) {
                throw new SQLException("prior approval " + priorApprovalId + " changed unexpectedly under lock; aborting");
            }
            return new SupersedingIssuanceResult(newRecord.approvalId(), TransitionOutcome.SUCCESS);
        });
    }

    private TransitionOutcome supersedeWithinTransaction(Connection connection, String approvalId, Instant supersededAt, String supersedingApprovalId, String supersedingPlanSha256) throws SQLException {
        Optional<CasSnapshot> snapshot = selectForUpdate(connection, approvalId);
        if (snapshot.isEmpty()) {
            return TransitionOutcome.NOT_FOUND;
        }
        if (snapshot.get().status() != ApprovalStatus.ACTIVE) {
            return TransitionOutcome.ALREADY_TRANSITIONED;
        }
        int updated = executeSupersedeUpdate(connection, approvalId, snapshot.get().version(), supersededAt, supersedingApprovalId, supersedingPlanSha256);
        return updated == 1 ? TransitionOutcome.SUCCESS : TransitionOutcome.ALREADY_TRANSITIONED;
    }

    private int executeSupersedeUpdate(Connection connection, String approvalId, long expectedVersion, Instant supersededAt, String supersedingApprovalId, String supersedingPlanSha256) throws SQLException {
        String sql = """
                UPDATE approval_records
                SET status = 'SUPERSEDED', superseded_at = ?, superseded_by_approval_id = ?, superseding_plan_sha256 = ?,
                    version = version + 1, updated_at = ?
                WHERE approval_id = ? AND status = 'ACTIVE' AND version = ?
                """;
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            setInstant(ps, 1, supersededAt);
            ps.setString(2, supersedingApprovalId);
            ps.setString(3, supersedingPlanSha256);
            setInstant(ps, 4, supersededAt);
            ps.setString(5, approvalId);
            ps.setLong(6, expectedVersion);
            return ps.executeUpdate();
        }
    }

    private void insertRecord(Connection connection, ApprovalRecord record) throws SQLException {
        String sql = """
                INSERT INTO approval_records (
                    approval_id, repository, commit_sha, environment, plan_sha256,
                    approved_by, approved_at, expires_at, status,
                    reviewed_pr_reference, ci_run_reference,
                    revoked_at, revoked_by, revocation_reason,
                    superseded_at, superseded_by_approval_id, superseding_plan_sha256,
                    version, created_at, updated_at
                ) VALUES (?,?,?,?,?, ?,?,?,?, ?,?, ?,?,?, ?,?,?, ?,?,?)
                """;
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            int i = 1;
            ps.setString(i++, record.approvalId());
            ps.setString(i++, record.repository());
            ps.setString(i++, record.commitSha());
            ps.setString(i++, record.environment());
            ps.setString(i++, record.planSha256());
            ps.setString(i++, record.approvedBy());
            setInstant(ps, i++, record.approvedAt());
            setInstant(ps, i++, record.expiresAt());
            ps.setString(i++, record.status().name());
            ps.setString(i++, record.provenance() == null ? null : record.provenance().reviewedPrReference());
            ps.setString(i++, record.provenance() == null ? null : record.provenance().ciRunReference());
            setInstant(ps, i++, record.revokedAt());
            ps.setString(i++, record.revokedBy());
            ps.setString(i++, record.revokedReason());
            setInstant(ps, i++, record.supersededAt());
            ps.setString(i++, record.supersedingApprovalId());
            ps.setString(i++, record.supersedingPlanSha256());
            ps.setLong(i++, 0L);
            setInstant(ps, i++, record.approvedAt());
            setInstant(ps, i, record.approvedAt());
            ps.executeUpdate();
        } catch (SQLException e) {
            if ("23505".equals(e.getSQLState())) {
                throw new IllegalStateException("approvalId already exists: " + record.approvalId(), e);
            }
            throw e;
        }
    }

    private Optional<CasSnapshot> selectForUpdate(Connection connection, String approvalId) throws SQLException {
        String sql = "SELECT status, version FROM approval_records WHERE approval_id = ? FOR UPDATE";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, approvalId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return Optional.empty();
                }
                return Optional.of(new CasSnapshot(ApprovalStatus.valueOf(rs.getString("status")), rs.getLong("version")));
            }
        }
    }

    private ApprovalRecord mapRow(ResultSet rs) throws SQLException {
        return new ApprovalRecord(
                rs.getString("approval_id"),
                rs.getString("repository"),
                rs.getString("commit_sha"),
                rs.getString("environment"),
                rs.getString("plan_sha256"),
                rs.getString("approved_by"),
                readInstant(rs, "approved_at"),
                readInstant(rs, "expires_at"),
                ApprovalStatus.valueOf(rs.getString("status")),
                new ApprovalProvenance(rs.getString("reviewed_pr_reference"), rs.getString("ci_run_reference")),
                readInstant(rs, "revoked_at"),
                rs.getString("revoked_by"),
                rs.getString("revocation_reason"),
                readInstant(rs, "superseded_at"),
                rs.getString("superseded_by_approval_id"),
                rs.getString("superseding_plan_sha256")
        );
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

    @FunctionalInterface
    private interface TransactionalWork<T> {
        T execute(Connection connection) throws SQLException;
    }

    private <T> T withTransaction(TransactionalWork<T> work) {
        Connection connection;
        try {
            connection = dataSource.getConnection();
        } catch (SQLException | RuntimeException e) {
            // A disposed/unavailable connection pool (e.g. H2's JdbcConnectionPool after close())
            // can throw an unchecked exception here rather than SQLException - it must still be
            // reported as an infrastructure failure, not left to propagate as whatever exception
            // type the underlying pool implementation happens to throw, which a caller could
            // otherwise mistake for a domain-level outcome (e.g. IllegalStateException is also
            // what create() throws for a legitimate duplicate-id case).
            throw new ApprovalPersistenceException("could not obtain a database connection", e);
        }
        try {
            T result;
            try {
                connection.setAutoCommit(false);
                result = work.execute(connection);
            } catch (SQLException | RuntimeException e) {
                rollbackQuietly(connection);
                if (e instanceof IllegalStateException ise) {
                    throw ise;
                }
                throw new ApprovalPersistenceException("approval persistence transaction failed", e);
            }
            try {
                connection.commit();
            } catch (SQLException e) {
                rollbackQuietly(connection);
                throw new ApprovalPersistenceException("approval persistence transaction failed to commit", e);
            }
            return result;
        } finally {
            closeQuietly(connection);
        }
    }

    private static void rollbackQuietly(Connection connection) {
        try {
            connection.rollback();
        } catch (SQLException ignored) {
            // best-effort - the connection is being closed regardless, and the original failure
            // is what gets reported to the caller
        }
    }

    private static void closeQuietly(Connection connection) {
        try {
            connection.close();
        } catch (SQLException ignored) {
            // nothing further to do
        }
    }

    private record CasSnapshot(ApprovalStatus status, long version) {
    }
}
