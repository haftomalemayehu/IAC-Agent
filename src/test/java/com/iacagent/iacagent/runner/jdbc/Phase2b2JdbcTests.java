package com.iacagent.iacagent.runner.jdbc;

import com.iacagent.iacagent.approval.ApprovalValidationReasonCode;
import com.iacagent.iacagent.runner.RunnerClaimOutcome;
import com.iacagent.iacagent.runner.RunnerEvidence;
import com.iacagent.iacagent.runner.RunnerLedgerPersistenceException;
import com.iacagent.iacagent.runner.RunnerOperation;
import com.iacagent.iacagent.runner.RunnerReasonCode;
import com.iacagent.iacagent.runner.RunnerRequest;
import com.iacagent.iacagent.runner.RunnerState;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.sql.DataSource;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Restart- and concurrency-durability proof for {@link JdbcRunnerLedgerRepository}, against a real
 * H2 database rather than a synchronized in-memory test double - the domain-level claim/record/find
 * semantics are already covered by {@code com.iacagent.iacagent.runner.Phase2b2Tests} against
 * {@code InMemoryRunnerLedgerRepository}; this file exists specifically to prove those semantics
 * survive an actual process restart and a real concurrent transaction race, per the Phase 2B-2
 * design doc's Gate B caveat (H2 here is the reference/acceptance backend, not a claim that it
 * satisfies the production hard gate - see docs/phase-2b2-runner-hardening.md).
 */
class Phase2b2JdbcTests {

    private static final Instant NOW = Instant.parse("2026-09-10T00:00:00Z");

    private RunnerRequest sampleRequest(String id, String artifactId, String approvalId) {
        return new RunnerRequest(id, "owner/repository", "c".repeat(40), "nonprod", artifactId,
                "sha256:aaa", "1.6.6", "sha256:lock", approvalId, RunnerOperation.PREPARE_EXECUTION);
    }

    private RunnerEvidence terminalEvidenceFor(RunnerRequest request, RunnerState finalState, List<RunnerReasonCode> reasonCodes) {
        return new RunnerEvidence(
                request.runnerRequestId(), "runner-1", "class-a", Set.of("nonprod"),
                request.requestedOperation(), request.repository(), request.commitSha(), request.environment(),
                request.planArtifactId(), request.planSha256(), request.planSha256(),
                request.terraformVersion(), request.terraformVersion(), request.providerLockHash(), request.providerLockHash(),
                request.approvalId(), ApprovalValidationReasonCode.VALID, finalState, reasonCodes, NOW, NOW.plusSeconds(1), null);
    }

    // A claim made before a restart, with no terminal evidence yet recorded, remains CLAIMED (never
    // silently forgotten/treated as new) after a fresh repository object reopens the same file.
    @Test
    void claimedButIncompleteRequestRemainsConsumedAfterRestart(@TempDir Path dir) {
        String requestId;
        RunnerRequest request = sampleRequest("req-incomplete", "artifact-1", "approval-1");
        requestId = request.runnerRequestId();

        JdbcRunnerLedgerRepository repoA = JdbcRunnerLedgerRepository.openH2FileBacked(dir);
        assertEquals(RunnerClaimOutcome.CLAIMED, repoA.claim(request, NOW));
        repoA.close(); // simulate a crash: no recordTerminalEvidence ever ran

        JdbcRunnerLedgerRepository repoB = JdbcRunnerLedgerRepository.openH2FileBacked(dir);
        try {
            assertEquals(RunnerClaimOutcome.INCOMPLETE_PRIOR_CLAIM, repoB.claim(request, NOW.plusSeconds(60)),
                    "a crashed-but-claimed request must block as ambiguous/incomplete, not be treated as fresh");
            assertTrue(repoB.findHistoricalEvidence(requestId).isEmpty());
        } finally {
            repoB.close();
        }
    }

    // Completed evidence and its retrievability as historical evidence both survive restart.
    @Test
    void completedEvidenceAndHistoricalLookupSurviveRestart(@TempDir Path dir) {
        RunnerRequest request = sampleRequest("req-completed", "artifact-1", "approval-1");
        JdbcRunnerLedgerRepository repoA = JdbcRunnerLedgerRepository.openH2FileBacked(dir);
        repoA.claim(request, NOW);
        repoA.recordTerminalEvidence(terminalEvidenceFor(request, RunnerState.READY_FOR_FUTURE_EXECUTION, List.of()));
        repoA.close();

        JdbcRunnerLedgerRepository repoB = JdbcRunnerLedgerRepository.openH2FileBacked(dir);
        try {
            RunnerEvidence found = repoB.findHistoricalEvidence("req-completed").orElseThrow();
            assertEquals(RunnerState.READY_FOR_FUTURE_EXECUTION, found.finalState());
            assertEquals("runner-1", found.runnerId());
            assertEquals("class-a", found.runnerClass());
            assertEquals(Set.of("nonprod"), found.runnerEnvironmentScope());
            // a resubmission after restart must still be blocked, never re-executed
            assertEquals(RunnerClaimOutcome.DUPLICATE_SAME_FINGERPRINT, repoB.claim(request, NOW.plusSeconds(60)));
        } finally {
            repoB.close();
        }
    }

    // Same id, different content, blocks with FINGERPRINT_MISMATCH even after restart.
    @Test
    void fingerprintMismatchAfterRestartStillBlocks(@TempDir Path dir) {
        RunnerRequest original = sampleRequest("req-fp", "artifact-1", "approval-1");
        JdbcRunnerLedgerRepository repoA = JdbcRunnerLedgerRepository.openH2FileBacked(dir);
        repoA.claim(original, NOW);
        repoA.recordTerminalEvidence(terminalEvidenceFor(original, RunnerState.READY_FOR_FUTURE_EXECUTION, List.of()));
        repoA.close();

        RunnerRequest differentContentSameId = sampleRequest("req-fp", "artifact-DIFFERENT", "approval-1");
        JdbcRunnerLedgerRepository repoB = JdbcRunnerLedgerRepository.openH2FileBacked(dir);
        try {
            assertEquals(RunnerClaimOutcome.FINGERPRINT_MISMATCH, repoB.claim(differentContentSameId, NOW.plusSeconds(60)));
            // the original completed record must remain exactly as it was - never overwritten by the mismatch attempt
            assertEquals("artifact-1", repoB.findHistoricalEvidence("req-fp").orElseThrow().planArtifactId());
        } finally {
            repoB.close();
        }
    }

    // A duplicate-id claim attempt must never mutate the original CLAIMED/COMPLETED row.
    @Test
    void duplicateClaimAttemptDoesNotMutateTheOriginalRow(@TempDir Path dir) {
        JdbcRunnerLedgerRepository repo = JdbcRunnerLedgerRepository.openH2FileBacked(dir);
        try {
            RunnerRequest original = sampleRequest("req-immutable", "artifact-1", "approval-1");
            repo.claim(original, NOW);
            repo.recordTerminalEvidence(terminalEvidenceFor(original, RunnerState.READY_FOR_FUTURE_EXECUTION, List.of()));
            RunnerEvidence before = repo.findHistoricalEvidence("req-immutable").orElseThrow();

            repo.claim(sampleRequest("req-immutable", "artifact-1", "approval-1"), NOW.plusSeconds(60)); // identical fingerprint
            repo.claim(sampleRequest("req-immutable", "artifact-OTHER", "approval-1"), NOW.plusSeconds(60)); // mismatched fingerprint

            RunnerEvidence after = repo.findHistoricalEvidence("req-immutable").orElseThrow();
            assertEquals(before, after, "no duplicate/mismatched claim attempt may alter the original record");
        } finally {
            repo.close();
        }
    }

    // Exactly one of many real concurrent transactions claiming the same previously-unseen id wins.
    @Test
    void concurrentClaimsOnTheSameIdHaveExactlyOneWinnerAgainstTheDurableBackend(@TempDir Path dir) throws InterruptedException {
        JdbcRunnerLedgerRepository repo = JdbcRunnerLedgerRepository.openH2FileBacked(dir);
        try {
            RunnerRequest request = sampleRequest("req-race", "artifact-1", "approval-1");
            int threadCount = 8;
            ExecutorService pool = Executors.newFixedThreadPool(threadCount);
            CountDownLatch ready = new CountDownLatch(threadCount);
            CountDownLatch go = new CountDownLatch(1);
            AtomicInteger claimed = new AtomicInteger(0);
            AtomicInteger incomplete = new AtomicInteger(0);

            for (int i = 0; i < threadCount; i++) {
                pool.submit(() -> {
                    ready.countDown();
                    awaitUninterruptibly(go);
                    RunnerClaimOutcome outcome = repo.claim(request, NOW);
                    if (outcome == RunnerClaimOutcome.CLAIMED) claimed.incrementAndGet();
                    if (outcome == RunnerClaimOutcome.INCOMPLETE_PRIOR_CLAIM) incomplete.incrementAndGet();
                });
            }
            ready.await();
            go.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(15, TimeUnit.SECONDS));

            assertEquals(1, claimed.get(), "exactly one real concurrent transaction may claim a previously unseen id");
            assertEquals(threadCount - 1, incomplete.get());
        } finally {
            repo.close();
        }
    }

    // Concurrent claims with different fingerprints for the same id: exactly one wins, the other
    // sees FINGERPRINT_MISMATCH, and the winner's row is never overwritten.
    @Test
    void concurrentClaimsWithDifferentFingerprintsAgainstTheDurableBackendDoNotCorruptEachOther(@TempDir Path dir) throws InterruptedException {
        JdbcRunnerLedgerRepository repo = JdbcRunnerLedgerRepository.openH2FileBacked(dir);
        try {
            RunnerRequest requestA = sampleRequest("req-race-fp", "artifact-A", "approval-A");
            RunnerRequest requestB = sampleRequest("req-race-fp", "artifact-B", "approval-B");

            ExecutorService pool = Executors.newFixedThreadPool(2);
            CountDownLatch ready = new CountDownLatch(2);
            CountDownLatch go = new CountDownLatch(1);
            AtomicReference<RunnerClaimOutcome> outcomeA = new AtomicReference<>();
            AtomicReference<RunnerClaimOutcome> outcomeB = new AtomicReference<>();
            pool.submit(() -> {
                ready.countDown();
                awaitUninterruptibly(go);
                outcomeA.set(repo.claim(requestA, NOW));
            });
            pool.submit(() -> {
                ready.countDown();
                awaitUninterruptibly(go);
                outcomeB.set(repo.claim(requestB, NOW));
            });
            ready.await();
            go.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(15, TimeUnit.SECONDS));

            boolean exactlyOneClaimed = (outcomeA.get() == RunnerClaimOutcome.CLAIMED) ^ (outcomeB.get() == RunnerClaimOutcome.CLAIMED);
            assertTrue(exactlyOneClaimed);
            RunnerClaimOutcome loser = outcomeA.get() == RunnerClaimOutcome.CLAIMED ? outcomeB.get() : outcomeA.get();
            assertEquals(RunnerClaimOutcome.FINGERPRINT_MISMATCH, loser);

            RunnerRequest winner = outcomeA.get() == RunnerClaimOutcome.CLAIMED ? requestA : requestB;
            repo.recordTerminalEvidence(terminalEvidenceFor(winner, RunnerState.READY_FOR_FUTURE_EXECUTION, List.of()));
            assertEquals(winner.planArtifactId(), repo.findHistoricalEvidence("req-race-fp").orElseThrow().planArtifactId());
        } finally {
            repo.close();
        }
    }

    // Terminal evidence can never be recorded twice for the same id, even sequentially.
    @Test
    void terminalEvidenceCannotBeRecordedTwiceForTheSameId(@TempDir Path dir) {
        JdbcRunnerLedgerRepository repo = JdbcRunnerLedgerRepository.openH2FileBacked(dir);
        try {
            RunnerRequest request = sampleRequest("req-double", "artifact-1", "approval-1");
            repo.claim(request, NOW);
            repo.recordTerminalEvidence(terminalEvidenceFor(request, RunnerState.READY_FOR_FUTURE_EXECUTION, List.of()));

            assertThrows(IllegalStateException.class,
                    () -> repo.recordTerminalEvidence(terminalEvidenceFor(request, RunnerState.READY_FOR_FUTURE_EXECUTION, List.of())));
        } finally {
            repo.close();
        }
    }

    // Storage failure (pool disposed) fails closed - never a false CLAIMED/COMPLETED outcome, never
    // a fallback to memory.
    @Test
    void durableStoreFailurePropagatesAndNeverFallsBackToMemory(@TempDir Path dir) {
        JdbcRunnerLedgerRepository repo = JdbcRunnerLedgerRepository.openH2FileBacked(dir);
        repo.close();

        RunnerRequest request = sampleRequest("req-after-close", "artifact-1", "approval-1");
        assertThrows(RunnerLedgerPersistenceException.class, () -> repo.claim(request, NOW));
        assertThrows(RunnerLedgerPersistenceException.class, () -> repo.findHistoricalEvidence("anything"));
        // Structural note (mirrors the approval subsystem's own equivalent test): there is no catch
        // block anywhere in JdbcRunnerLedgerRepository or ControlledRunner that catches
        // RunnerLedgerPersistenceException and substitutes an InMemoryRunnerLedgerRepository or any
        // other fallback result - confirmed by inspection, and by the fact that the assertThrows
        // calls above would not otherwise observe an exception at all.
    }

    // Simulated failure partway through the claim INSERT must not leave a half-written row that a
    // later claim attempt could misclassify.
    @Test
    void simulatedFailureDuringClaimInsertLeavesNoPartialRow(@TempDir Path dir) {
        DataSource realDataSource = JdbcRunnerLedgerRepository.createMigratedH2FileBackedDataSource(dir);
        DataSource faultyDataSource = FaultInjectingDataSource.throwingOnExecuteUpdateCall(realDataSource, 1);
        JdbcRunnerLedgerRepository faultyRepo = new JdbcRunnerLedgerRepository(faultyDataSource);
        RunnerRequest request = sampleRequest("req-fault", "artifact-1", "approval-1");

        assertThrows(RunnerLedgerPersistenceException.class, () -> faultyRepo.claim(request, NOW));

        JdbcRunnerLedgerRepository cleanRepo = new JdbcRunnerLedgerRepository(realDataSource);
        try {
            assertEquals(RunnerClaimOutcome.CLAIMED, cleanRepo.claim(request, NOW.plusSeconds(1)),
                    "the failed insert must not have left a row behind - the id must still be genuinely unclaimed");
        } finally {
            cleanRepo.close();
        }
    }

    private static void awaitUninterruptibly(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
    }
}
