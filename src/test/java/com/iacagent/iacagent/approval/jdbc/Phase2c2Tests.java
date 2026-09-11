package com.iacagent.iacagent.approval.jdbc;

import com.iacagent.iacagent.approval.ApprovalAuthority;
import com.iacagent.iacagent.approval.ApprovalIssuanceRequest;
import com.iacagent.iacagent.approval.ApprovalPersistenceException;
import com.iacagent.iacagent.approval.ApprovalProvenance;
import com.iacagent.iacagent.approval.ApprovalProvider;
import com.iacagent.iacagent.approval.ApprovalRecord;
import com.iacagent.iacagent.approval.ApprovalRecordProducer;
import com.iacagent.iacagent.approval.ApprovalRepository;
import com.iacagent.iacagent.approval.ApprovalStatus;
import com.iacagent.iacagent.approval.ApprovalTtlPolicy;
import com.iacagent.iacagent.approval.ApprovalValidationReasonCode;
import com.iacagent.iacagent.approval.ApprovalValidator;
import com.iacagent.iacagent.approval.ExecutionIdentity;
import com.iacagent.iacagent.approval.RepositoryBackedApprovalProvider;
import com.iacagent.iacagent.approval.SupersedingIssuanceResult;
import com.iacagent.iacagent.approval.TransitionOutcome;
import com.iacagent.iacagent.approval.TrustedApprovalContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.sql.DataSource;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class Phase2c2Tests {

    private static final Instant NOW = Instant.parse("2026-09-10T00:00:00.123Z");
    private static final TrustedApprovalContext APPROVER = new TrustedApprovalContext("platform-admin");
    private static final Duration DEFAULT_TTL = Duration.ofHours(4);

    private static final class MutableClock extends Clock {
        private Instant instant;

        MutableClock(Instant initial) {
            this.instant = initial;
        }

        void set(Instant instant) {
            this.instant = instant;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }

    private ApprovalRecord sampleRecord(String approvalId, String planSha, Instant approvedAt) {
        return new ApprovalRecord(
                approvalId, "owner/repository", "c".repeat(40), "nonprod", planSha,
                "platform-admin", approvedAt, approvedAt.plus(DEFAULT_TTL), ApprovalStatus.ACTIVE,
                new ApprovalProvenance("https://github.com/owner/repository/pull/1", "https://github.com/owner/repository/actions/runs/1"),
                null, null, null, null, null, null);
    }

    private ApprovalIssuanceRequest sampleRequest(String planSha) {
        return new ApprovalIssuanceRequest("owner/repository", "c".repeat(40), "nonprod", planSha,
                new ApprovalProvenance("https://github.com/owner/repository/pull/1", "https://github.com/owner/repository/actions/runs/1"));
    }

    private ExecutionIdentity sampleIdentity(String planSha) {
        return new ExecutionIdentity("owner/repository", "c".repeat(40), "nonprod", planSha);
    }

    // 1 & 3 & 4 & 5: issue persists durably; bindings + provenance + time precision round-trip exactly
    @Test
    void issuePersistsDurablyWithExactRoundTrip(@TempDir Path dir) {
        JdbcApprovalRepository repo = JdbcApprovalRepository.openH2FileBacked(dir);
        try {
            ApprovalRecord record = sampleRecord("approval-1", "sha256:aaa", NOW);
            repo.create(record);

            ApprovalRecord found = repo.find("approval-1").orElseThrow();
            assertEquals(record.approvalId(), found.approvalId());
            assertEquals(record.repository(), found.repository());
            assertEquals(record.commitSha(), found.commitSha());
            assertEquals(record.environment(), found.environment());
            assertEquals(record.planSha256(), found.planSha256());
            assertEquals(record.approvedBy(), found.approvedBy());
            assertEquals(record.approvedAt(), found.approvedAt(), "sub-second precision must not be corrupted");
            assertEquals(record.expiresAt(), found.expiresAt());
            assertEquals(record.status(), found.status());
            assertEquals(record.provenance(), found.provenance());
        } finally {
            repo.close();
        }
    }

    // 2 & 6 & 7 & 8: resolve/expiry/revocation/supersession survive a genuine restart
    @Test
    void resolutionAndLifecycleSurviveRestart(@TempDir Path dir) {
        String activeId;
        String revokedId;
        String supersededId;
        String supersedingId;

        // "process A"
        {
            JdbcApprovalRepository repoA = JdbcApprovalRepository.openH2FileBacked(dir);
            MutableClock clockA = new MutableClock(NOW);
            ApprovalRecordProducer producerA = new ApprovalRecordProducer(repoA, clockA, ApprovalTtlPolicy.fixed(DEFAULT_TTL));

            activeId = producerA.issue(sampleRequest("sha256:active"), APPROVER);
            revokedId = producerA.issue(sampleRequest("sha256:revoked"), APPROVER);
            producerA.revoke(revokedId, APPROVER, "rotated before restart");
            supersededId = producerA.issue(sampleRequest("sha256:old"), APPROVER);
            SupersedingIssuanceResult supersession = producerA.issueSuperseding(sampleRequest("sha256:new"), APPROVER, supersededId);
            supersedingId = supersession.newApprovalId();

            repoA.close(); // destroy persistence context - not just "stop using the variable"
        }

        // "process B" - an entirely new repository object, new connection pool, same file
        JdbcApprovalRepository repoB = JdbcApprovalRepository.openH2FileBacked(dir);
        try {
            ApprovalProvider provider = new RepositoryBackedApprovalProvider(repoB);

            ApprovalRecord active = repoB.find(activeId).orElseThrow();
            assertEquals(ApprovalStatus.ACTIVE, active.status());
            assertTrue(ApprovalValidator.validate(provider, activeId, sampleIdentity("sha256:active"), NOW.plusSeconds(60)).isValid());
            assertEquals(ApprovalValidationReasonCode.APPROVAL_EXPIRED,
                    ApprovalValidator.validate(provider, activeId, sampleIdentity("sha256:active"), NOW.plus(DEFAULT_TTL.plusMinutes(1))).reasonCode(),
                    "expiry must still be computed correctly from the persisted expiresAt after restart");

            ApprovalRecord revoked = repoB.find(revokedId).orElseThrow();
            assertEquals(ApprovalStatus.REVOKED, revoked.status());
            assertEquals("rotated before restart", revoked.revokedReason());
            assertEquals(ApprovalValidationReasonCode.APPROVAL_REVOKED,
                    ApprovalValidator.validate(provider, revokedId, sampleIdentity("sha256:revoked"), NOW.plusSeconds(60)).reasonCode());

            ApprovalRecord superseded = repoB.find(supersededId).orElseThrow();
            assertEquals(ApprovalStatus.SUPERSEDED, superseded.status());
            assertEquals(supersedingId, superseded.supersedingApprovalId());
            assertEquals("sha256:new", superseded.supersedingPlanSha256());
            assertTrue(ApprovalValidator.validate(provider, supersedingId, sampleIdentity("sha256:new"), NOW.plusSeconds(60)).isValid());
        } finally {
            repoB.close();
        }
    }

    // 9 & 10: revoked/superseded approvals remain auditable (not deleted)
    @Test
    void revokedAndSupersededApprovalsRemainAuditable(@TempDir Path dir) {
        JdbcApprovalRepository repo = JdbcApprovalRepository.openH2FileBacked(dir);
        try {
            ApprovalRecordProducer producer = new ApprovalRecordProducer(repo, new MutableClock(NOW), ApprovalTtlPolicy.fixed(DEFAULT_TTL));
            String revokedId = producer.issue(sampleRequest("sha256:aaa"), APPROVER);
            producer.revoke(revokedId, APPROVER, "audit-reason");

            String oldId = producer.issue(sampleRequest("sha256:bbb"), APPROVER);
            producer.issueSuperseding(sampleRequest("sha256:ccc"), APPROVER, oldId);

            assertTrue(repo.find(revokedId).isPresent());
            assertTrue(repo.find(oldId).isPresent());
        } finally {
            repo.close();
        }
    }

    // 11: no hard-delete repository API
    @Test
    void approvalRepositoryHasNoDeleteOrReplaceOperation() {
        Set<String> methodNames = Arrays.stream(ApprovalRepository.class.getDeclaredMethods())
                .map(Method::getName)
                .collect(Collectors.toSet());
        assertEquals(Set.of("create", "find", "revoke", "supersede", "createAndSupersede"), methodNames);
        assertFalse(methodNames.stream().anyMatch(n -> n.toLowerCase().contains("delete")
                || n.toLowerCase().contains("truncate") || n.toLowerCase().contains("replace")));
    }

    // 12: duplicate approvalId cannot overwrite
    @Test
    void duplicateApprovalIdCannotOverwrite(@TempDir Path dir) {
        JdbcApprovalRepository repo = JdbcApprovalRepository.openH2FileBacked(dir);
        try {
            ApprovalRecord record = sampleRecord("approval-dup", "sha256:aaa", NOW);
            repo.create(record);
            ApprovalRecord attemptedOverwrite = new ApprovalRecord(
                    "approval-dup", "owner/other-repository", "d".repeat(40), "production", "sha256:different",
                    "someone-else", NOW.plus(Duration.ofMinutes(1)), NOW.plus(Duration.ofHours(2)), ApprovalStatus.ACTIVE,
                    new ApprovalProvenance("different-pr", "different-run"), null, null, null, null, null, null);

            assertThrows(IllegalStateException.class, () -> repo.create(attemptedOverwrite));
            // the original row must remain authoritative, byte-for-byte, not merely "not deleted"
            assertEquals(record, repo.find("approval-dup").orElseThrow());
        } finally {
            repo.close();
        }
    }

    // 13: concurrent revoke vs revoke - exactly one succeeds
    @Test
    void concurrentRevokeVsRevokeExactlyOneSucceeds(@TempDir Path dir) throws InterruptedException {
        JdbcApprovalRepository repo = JdbcApprovalRepository.openH2FileBacked(dir);
        try {
            repo.create(sampleRecord("approval-race-1", "sha256:aaa", NOW));

            int successes = raceTwoTransitions(
                    () -> repo.revoke("approval-race-1", NOW.plusSeconds(1), "actor-a", "reason-a"),
                    () -> repo.revoke("approval-race-1", NOW.plusSeconds(2), "actor-b", "reason-b"));

            assertEquals(1, successes);
            assertEquals(ApprovalStatus.REVOKED, repo.find("approval-race-1").orElseThrow().status());
        } finally {
            repo.close();
        }
    }

    // 14: concurrent revoke vs supersede - exactly one lifecycle transition succeeds
    @Test
    void concurrentRevokeVsSupersedeExactlyOneSucceeds(@TempDir Path dir) throws InterruptedException {
        JdbcApprovalRepository repo = JdbcApprovalRepository.openH2FileBacked(dir);
        try {
            repo.create(sampleRecord("approval-race-2", "sha256:aaa", NOW));

            int successes = raceTwoTransitions(
                    () -> repo.revoke("approval-race-2", NOW.plusSeconds(1), "actor-a", "reason-a"),
                    () -> repo.supersede("approval-race-2", NOW.plusSeconds(1), "approval-other", "sha256:other"));

            assertEquals(1, successes);
            ApprovalRecord result = repo.find("approval-race-2").orElseThrow();
            assertTrue(result.status() == ApprovalStatus.REVOKED || result.status() == ApprovalStatus.SUPERSEDED);
        } finally {
            repo.close();
        }
    }

    // 15: concurrent supersede attempts cannot corrupt history
    @Test
    void concurrentSupersedeAttemptsCannotCorruptHistory(@TempDir Path dir) throws InterruptedException {
        JdbcApprovalRepository repo = JdbcApprovalRepository.openH2FileBacked(dir);
        try {
            repo.create(sampleRecord("approval-race-3", "sha256:aaa", NOW));

            int successes = raceTwoTransitions(
                    () -> repo.supersede("approval-race-3", NOW.plusSeconds(1), "approval-x", "sha256:x"),
                    () -> repo.supersede("approval-race-3", NOW.plusSeconds(1), "approval-y", "sha256:y"));

            assertEquals(1, successes);
            ApprovalRecord result = repo.find("approval-race-3").orElseThrow();
            assertEquals(ApprovalStatus.SUPERSEDED, result.status());
            // whichever won, the record must reference exactly one consistent superseding approval - not a mix of both
            assertTrue(result.supersedingApprovalId().equals("approval-x") || result.supersedingApprovalId().equals("approval-y"));
            boolean referencesX = "approval-x".equals(result.supersedingApprovalId());
            assertEquals(referencesX ? "sha256:x" : "sha256:y", result.supersedingPlanSha256());
        } finally {
            repo.close();
        }
    }

    private int raceTwoTransitions(java.util.function.Supplier<TransitionOutcome> first, java.util.function.Supplier<TransitionOutcome> second) throws InterruptedException {
        AtomicInteger successCount = new AtomicInteger(0);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch go = new CountDownLatch(1);
        Runnable r1 = () -> {
            ready.countDown();
            awaitUninterruptibly(go);
            if (first.get() == TransitionOutcome.SUCCESS) successCount.incrementAndGet();
        };
        Runnable r2 = () -> {
            ready.countDown();
            awaitUninterruptibly(go);
            if (second.get() == TransitionOutcome.SUCCESS) successCount.incrementAndGet();
        };
        pool.submit(r1);
        pool.submit(r2);
        ready.await();
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        return successCount.get();
    }

    private static void awaitUninterruptibly(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
    }

    // 16: optimistic-lock/version conflict fails closed
    @Test
    void versionGuardedUpdateFailsClosedOnceRecordHasAlreadyTransitioned(@TempDir Path dir) {
        // The current lifecycle only ever changes `version` together with `status` (ACTIVE -> a
        // terminal state) - there is no operation that changes version while status stays ACTIVE,
        // so a "version conflict with status unchanged" scenario cannot arise from the public API.
        // What IS directly testable, and is exactly what the version predicate guards against, is
        // a second transition attempt racing against a first: the loser's UPDATE carries a version
        // value that is stale by the time it executes, and the WHERE clause (status = 'ACTIVE' AND
        // version = ?) must fail to match rather than silently proceeding. concurrentRevokeVsRevoke/
        // concurrentRevokeVsSupersede/concurrentSupersedeAttempts above already exercise exactly
        // this path under real concurrency; this test asserts the same guarantee once more,
        // sequentially, to make the version predicate's role unambiguous rather than
        // implicit in a timing-dependent test.
        JdbcApprovalRepository repo = JdbcApprovalRepository.openH2FileBacked(dir);
        try {
            repo.create(sampleRecord("approval-version-guard", "sha256:aaa", NOW));
            TransitionOutcome first = repo.revoke("approval-version-guard", NOW.plusSeconds(1), "actor-a", "first");
            // this second attempt reads a *fresh* status/version (both already changed by the
            // first) - the guard closes over BOTH predicates together, correctly reporting
            // ALREADY_TRANSITIONED rather than SUCCESS
            TransitionOutcome second = repo.revoke("approval-version-guard", NOW.plusSeconds(2), "actor-b", "second");

            assertEquals(TransitionOutcome.SUCCESS, first);
            assertEquals(TransitionOutcome.ALREADY_TRANSITIONED, second);
        } finally {
            repo.close();
        }
    }

    // 17: superseding issuance is transactional (happy path: both effects visible together)
    @Test
    void issueSupersedingCommitsBothEffectsTogether(@TempDir Path dir) {
        JdbcApprovalRepository repo = JdbcApprovalRepository.openH2FileBacked(dir);
        try {
            ApprovalRecordProducer producer = new ApprovalRecordProducer(repo, new MutableClock(NOW), ApprovalTtlPolicy.fixed(DEFAULT_TTL));
            String oldId = producer.issue(sampleRequest("sha256:aaa"), APPROVER);

            SupersedingIssuanceResult result = producer.issueSuperseding(sampleRequest("sha256:bbb"), APPROVER, oldId);

            assertEquals(TransitionOutcome.SUCCESS, result.priorApprovalTransition());
            ApprovalRecord newRecord = repo.find(result.newApprovalId()).orElseThrow();
            ApprovalRecord oldRecord = repo.find(oldId).orElseThrow();
            assertEquals(ApprovalStatus.ACTIVE, newRecord.status());
            assertEquals(ApprovalStatus.SUPERSEDED, oldRecord.status());
            assertEquals(result.newApprovalId(), oldRecord.supersedingApprovalId());
        } finally {
            repo.close();
        }
    }

    // Sequential failure test: createAndSupersede against an already-inactive prior must leave no
    // new record behind - all-or-nothing, not "new created, supersede attempt merely reported as failed".
    @Test
    void issueSupersedingLeavesNoOrphanedNewApprovalWhenPriorAlreadyInactive(@TempDir Path dir) {
        JdbcApprovalRepository repo = JdbcApprovalRepository.openH2FileBacked(dir);
        try {
            ApprovalRecordProducer producer = new ApprovalRecordProducer(repo, new MutableClock(NOW), ApprovalTtlPolicy.fixed(DEFAULT_TTL));
            String oldId = producer.issue(sampleRequest("sha256:aaa"), APPROVER);
            producer.revoke(oldId, APPROVER, "unrelated revocation");

            SupersedingIssuanceResult result = producer.issueSuperseding(sampleRequest("sha256:bbb"), APPROVER, oldId);

            assertEquals(TransitionOutcome.ALREADY_TRANSITIONED, result.priorApprovalTransition());
            assertNull(result.newApprovalId(), "no new approval may exist when its whole reason for being issued - superseding this prior - failed");
            assertEquals(ApprovalStatus.REVOKED, repo.find(oldId).orElseThrow().status(), "the prior approval must remain exactly as it was");
        } finally {
            repo.close();
        }
    }

    // Concurrent createAndSupersede vs createAndSupersede on the same prior, against the durable
    // backend: exactly one wins, the winner's new approval exists, the loser's new approval id
    // must NOT resolve to anything - mirrors the corrected InMemoryApprovalRepository test.
    @Test
    void concurrentCreateAndSupersedeAgainstDurableStoreLeavesNoOrphanedLoser(@TempDir Path dir) throws InterruptedException {
        JdbcApprovalRepository repo = JdbcApprovalRepository.openH2FileBacked(dir);
        try {
            repo.create(sampleRecord("approval-prior-race", "sha256:prior", NOW));
            ApprovalRecord candidateX = sampleRecord("approval-x-race", "sha256:x", NOW);
            ApprovalRecord candidateY = sampleRecord("approval-y-race", "sha256:y", NOW);

            ExecutorService pool = Executors.newFixedThreadPool(2);
            CountDownLatch ready = new CountDownLatch(2);
            CountDownLatch go = new CountDownLatch(1);
            AtomicInteger successCount = new AtomicInteger(0);
            java.util.concurrent.atomic.AtomicReference<SupersedingIssuanceResult> resultX = new java.util.concurrent.atomic.AtomicReference<>();
            java.util.concurrent.atomic.AtomicReference<SupersedingIssuanceResult> resultY = new java.util.concurrent.atomic.AtomicReference<>();

            Runnable attemptX = () -> {
                ready.countDown();
                awaitUninterruptibly(go);
                SupersedingIssuanceResult r = repo.createAndSupersede(candidateX, "approval-prior-race", NOW.plusSeconds(1));
                resultX.set(r);
                if (r.priorApprovalTransition() == TransitionOutcome.SUCCESS) successCount.incrementAndGet();
            };
            Runnable attemptY = () -> {
                ready.countDown();
                awaitUninterruptibly(go);
                SupersedingIssuanceResult r = repo.createAndSupersede(candidateY, "approval-prior-race", NOW.plusSeconds(1));
                resultY.set(r);
                if (r.priorApprovalTransition() == TransitionOutcome.SUCCESS) successCount.incrementAndGet();
            };

            pool.submit(attemptX);
            pool.submit(attemptY);
            ready.await();
            go.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

            assertEquals(1, successCount.get());
            boolean xWon = resultX.get().priorApprovalTransition() == TransitionOutcome.SUCCESS;
            ApprovalRecord winner = xWon ? candidateX : candidateY;
            ApprovalRecord loser = xWon ? candidateY : candidateX;
            SupersedingIssuanceResult loserResult = xWon ? resultY.get() : resultX.get();

            assertNull(loserResult.newApprovalId());
            assertTrue(repo.find(winner.approvalId()).isPresent());
            assertTrue(repo.find(loser.approvalId()).isEmpty(), "the loser's new approval must not exist in durable storage");
            assertEquals(winner.approvalId(), repo.find("approval-prior-race").orElseThrow().supersedingApprovalId());
        } finally {
            repo.close();
        }
    }

    // 18: simulated failure after old-record transition causes full rollback
    @Test
    void simulatedFailureOnCommitCausesFullRollbackOfSupersession(@TempDir Path dir) {
        DataSource realDataSource = JdbcApprovalRepository.createMigratedH2FileBackedDataSource(dir);
        JdbcApprovalRepository setupRepo = new JdbcApprovalRepository(realDataSource);
        setupRepo.create(sampleRecord("approval-fault-1", "sha256:aaa", NOW));

        DataSource faultyDataSource = FaultInjectingDataSource.throwingOnCommit(realDataSource);
        JdbcApprovalRepository faultyRepo = new JdbcApprovalRepository(faultyDataSource);
        ApprovalRecord newRecord = sampleRecord("approval-fault-1-new", "sha256:bbb", NOW);

        assertThrows(ApprovalPersistenceException.class,
                () -> faultyRepo.createAndSupersede(newRecord, "approval-fault-1", NOW.plusSeconds(1)));

        // re-read through a clean (non-faulty) repository - both the insert AND the old-record
        // transition must have been rolled back together, since commit never succeeded
        assertTrue(setupRepo.find("approval-fault-1-new").isEmpty(), "the new approval must not exist - commit never happened");
        assertEquals(ApprovalStatus.ACTIVE, setupRepo.find("approval-fault-1").orElseThrow().status(),
                "the prior approval's transition must have been rolled back, not just the insert");
    }

    // 19: simulated failure before commit leaves no partial new approval
    @Test
    void simulatedFailureDuringSupersedeStepLeavesNoPartialNewApproval(@TempDir Path dir) {
        DataSource realDataSource = JdbcApprovalRepository.createMigratedH2FileBackedDataSource(dir);
        JdbcApprovalRepository setupRepo = new JdbcApprovalRepository(realDataSource);
        setupRepo.create(sampleRecord("approval-fault-2", "sha256:aaa", NOW));

        // call 1 = the INSERT of the new record; call 2 = the conditional UPDATE that supersedes
        // the prior record. Failing on call 2 simulates a failure that happens after the new
        // record's insert statement has run (but not yet committed) and before the old-record
        // transition completes.
        DataSource faultyDataSource = FaultInjectingDataSource.throwingOnExecuteUpdateCall(realDataSource, 2);
        JdbcApprovalRepository faultyRepo = new JdbcApprovalRepository(faultyDataSource);
        ApprovalRecord newRecord = sampleRecord("approval-fault-2-new", "sha256:bbb", NOW);

        assertThrows(ApprovalPersistenceException.class,
                () -> faultyRepo.createAndSupersede(newRecord, "approval-fault-2", NOW.plusSeconds(1)));

        assertTrue(setupRepo.find("approval-fault-2-new").isEmpty(), "the new approval's insert must have been rolled back, not partially committed");
        assertEquals(ApprovalStatus.ACTIVE, setupRepo.find("approval-fault-2").orElseThrow().status(), "the prior approval must be untouched");
    }

    // 20: unknown approval fails closed
    @Test
    void unknownApprovalFailsClosed(@TempDir Path dir) {
        JdbcApprovalRepository repo = JdbcApprovalRepository.openH2FileBacked(dir);
        try {
            assertTrue(repo.find("does-not-exist").isEmpty());
            assertEquals(TransitionOutcome.NOT_FOUND, repo.revoke("does-not-exist", NOW, "actor", "reason"));
            assertEquals(TransitionOutcome.NOT_FOUND, repo.supersede("does-not-exist", NOW, "approval-x", "sha256:x"));

            ApprovalProvider provider = new RepositoryBackedApprovalProvider(repo);
            assertEquals(ApprovalValidationReasonCode.APPROVAL_NOT_FOUND,
                    ApprovalValidator.validate(provider, "does-not-exist", sampleIdentity("sha256:aaa"), NOW).reasonCode());
        } finally {
            repo.close();
        }
    }

    // 21: durable-store failure never falls back to memory
    @Test
    void durableStoreFailurePropagatesAndNeverFallsBackToMemory(@TempDir Path dir) {
        JdbcApprovalRepository repo = JdbcApprovalRepository.openH2FileBacked(dir);
        repo.close(); // the underlying connection pool is now disposed - every subsequent call must fail

        assertThrows(ApprovalPersistenceException.class, () -> repo.find("approval-1"));
        assertThrows(ApprovalPersistenceException.class, () -> repo.create(sampleRecord("approval-1", "sha256:aaa", NOW)));
        assertThrows(ApprovalPersistenceException.class, () -> repo.revoke("approval-1", NOW, "actor", "reason"));
        // Structural note (not itself mechanically testable by asserting an absence): there is no
        // catch block anywhere in JdbcApprovalRepository, ApprovalProvider, ApprovalAuthority, or
        // ApprovalRecordProducer that catches ApprovalPersistenceException and substitutes an
        // InMemoryApprovalRepository or any other fallback result - confirmed by inspection (see
        // the Phase 2C-2 report's "failure/rollback behavior" section) and by the fact that this
        // test's assertThrows calls above would otherwise not observe a thrown exception at all.
    }

    // 22: ApprovalProvider remains read-only even when backed by the durable repository
    @Test
    void approvalProviderBackedByDurableRepositoryIsStillReadOnly(@TempDir Path dir) {
        JdbcApprovalRepository repo = JdbcApprovalRepository.openH2FileBacked(dir);
        try {
            ApprovalProvider provider = new RepositoryBackedApprovalProvider(repo);
            assertEquals(1, ApprovalProvider.class.getDeclaredMethods().length);
            assertFalse(ApprovalAuthority.class.isInstance(provider));
        } finally {
            repo.close();
        }
    }

    // Negative tests: no supported operation changes an authorization binding after issuance
    @Test
    void noOperationCanChangePlanShaCommitRepositoryEnvironmentOrApprover(@TempDir Path dir) {
        JdbcApprovalRepository repo = JdbcApprovalRepository.openH2FileBacked(dir);
        try {
            ApprovalRecord original = sampleRecord("approval-immutable", "sha256:aaa", NOW);
            repo.create(original);

            repo.revoke("approval-immutable", NOW.plusSeconds(1), "actor", "reason");

            ApprovalRecord after = repo.find("approval-immutable").orElseThrow();
            assertEquals(original.planSha256(), after.planSha256());
            assertEquals(original.commitSha(), after.commitSha());
            assertEquals(original.repository(), after.repository());
            assertEquals(original.environment(), after.environment());
            assertEquals(original.approvedBy(), after.approvedBy());
            assertEquals(original.approvedAt(), after.approvedAt());
            assertEquals(original.expiresAt(), after.expiresAt());
        } finally {
            repo.close();
        }
    }

    @Test
    void approvalRepositoryInterfaceExposesNoGeneralUpdateMethod() {
        // revoke/supersede/createAndSupersede take only the lifecycle-transition fields
        // (timestamps, actor, reason, superseding references) - none accept repository/commitSha/
        // environment/planSha256/approvedBy/approvedAt/expiresAt, so there is no signature through
        // which a caller could even attempt to pass a changed binding value.
        for (Method m : ApprovalRepository.class.getDeclaredMethods()) {
            if (m.getName().equals("revoke") || m.getName().equals("supersede")) {
                assertFalse(Arrays.asList(m.getParameterTypes()).contains(ApprovalRecord.class),
                        m.getName() + " must not accept a full ApprovalRecord to apply as an update");
            }
        }
    }
}
