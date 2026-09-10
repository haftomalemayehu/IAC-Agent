package com.iacagent.iacagent.approval;

import org.junit.jupiter.api.Test;

import java.lang.reflect.RecordComponent;
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

class Phase2c1Tests {

    private static final Instant NOW = Instant.parse("2026-09-10T00:00:00Z");
    private static final TrustedApprovalContext APPROVER = new TrustedApprovalContext("platform-admin");
    private static final Duration DEFAULT_TTL = Duration.ofHours(4);

    /** Deterministic, settable test Clock - the sole time authority the producer consults. */
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

    private ApprovalIssuanceRequest baseRequest(String planSha) {
        return new ApprovalIssuanceRequest(
                "owner/repository",
                "c".repeat(40),
                "nonprod",
                planSha,
                new ApprovalProvenance("https://github.com/owner/repository/pull/1", "https://github.com/owner/repository/actions/runs/1"));
    }

    private ExecutionIdentity baseIdentity(String planSha) {
        return new ExecutionIdentity("owner/repository", "c".repeat(40), "nonprod", planSha);
    }

    private ApprovalRecordProducer producer(InMemoryApprovalRepository repo, Clock clock) {
        return new ApprovalRecordProducer(repo, clock, ApprovalTtlPolicy.fixed(DEFAULT_TTL));
    }

    // 1. valid approval resolves and validates
    @Test
    void validApprovalResolvesAndValidates() {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String id = producer(repo, new MutableClock(NOW)).issue(baseRequest("sha256:aaa"), APPROVER);

        ApprovalProvider provider = new RepositoryBackedApprovalProvider(repo);
        ApprovalValidationResult result = ApprovalValidator.validate(provider, id, baseIdentity("sha256:aaa"), NOW);

        assertTrue(result.isValid());
        assertEquals(ApprovalValidationReasonCode.VALID, result.reasonCode());
        assertEquals(id, result.resolvedRecord().approvalId());
    }

    // 2. unknown approval fails closed
    @Test
    void unknownApprovalFailsClosed() {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        ApprovalProvider provider = new RepositoryBackedApprovalProvider(repo);

        ApprovalValidationResult result = ApprovalValidator.validate(provider, "approval-does-not-exist", baseIdentity("sha256:aaa"), NOW);

        assertFalse(result.isValid());
        assertEquals(ApprovalValidationReasonCode.APPROVAL_NOT_FOUND, result.reasonCode());
        assertNull(result.resolvedRecord());
    }

    // 3. expired approval fails
    @Test
    void expiredApprovalFails() {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String id = producer(repo, new MutableClock(NOW)).issue(baseRequest("sha256:aaa"), APPROVER);

        ApprovalProvider provider = new RepositoryBackedApprovalProvider(repo);
        Instant afterExpiry = NOW.plus(Duration.ofHours(5));
        ApprovalValidationResult result = ApprovalValidator.validate(provider, id, baseIdentity("sha256:aaa"), afterExpiry);

        assertEquals(ApprovalValidationReasonCode.APPROVAL_EXPIRED, result.reasonCode());
    }

    // 4. revoked approval fails
    @Test
    void revokedApprovalFails() {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        ApprovalRecordProducer producer = producer(repo, new MutableClock(NOW));
        String id = producer.issue(baseRequest("sha256:aaa"), APPROVER);

        TransitionOutcome outcome = producer.revoke(id, APPROVER, "credentials rotated");
        assertEquals(TransitionOutcome.SUCCESS, outcome);

        ApprovalProvider provider = new RepositoryBackedApprovalProvider(repo);
        ApprovalValidationResult result = ApprovalValidator.validate(provider, id, baseIdentity("sha256:aaa"), NOW.plus(Duration.ofMinutes(2)));

        assertEquals(ApprovalValidationReasonCode.APPROVAL_REVOKED, result.reasonCode());
    }

    // 5. superseded approval fails
    @Test
    void supersededApprovalFails() {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        ApprovalRecordProducer producer = producer(repo, new MutableClock(NOW));
        String oldId = producer.issue(baseRequest("sha256:aaa"), APPROVER);

        SupersedingIssuanceResult result = producer.issueSuperseding(baseRequest("sha256:bbb"), APPROVER, oldId);
        assertEquals(TransitionOutcome.SUCCESS, result.priorApprovalTransition());

        ApprovalProvider provider = new RepositoryBackedApprovalProvider(repo);
        ApprovalValidationResult oldResult = ApprovalValidator.validate(provider, oldId, baseIdentity("sha256:aaa"), NOW.plus(Duration.ofMinutes(2)));
        assertEquals(ApprovalValidationReasonCode.APPROVAL_SUPERSEDED, oldResult.reasonCode());

        ApprovalValidationResult newResult = ApprovalValidator.validate(provider, result.newApprovalId(), baseIdentity("sha256:bbb"), NOW.plus(Duration.ofMinutes(2)));
        assertTrue(newResult.isValid());
    }

    // 6. plan-hash mismatch fails
    @Test
    void planHashMismatchFails() {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String id = producer(repo, new MutableClock(NOW)).issue(baseRequest("sha256:aaa"), APPROVER);

        ApprovalProvider provider = new RepositoryBackedApprovalProvider(repo);
        ApprovalValidationResult result = ApprovalValidator.validate(provider, id, baseIdentity("sha256:different"), NOW);

        assertEquals(ApprovalValidationReasonCode.PLAN_HASH_MISMATCH, result.reasonCode());
    }

    // 7. commit mismatch fails
    @Test
    void commitMismatchFails() {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String id = producer(repo, new MutableClock(NOW)).issue(baseRequest("sha256:aaa"), APPROVER);

        ApprovalProvider provider = new RepositoryBackedApprovalProvider(repo);
        ExecutionIdentity wrongCommit = new ExecutionIdentity("owner/repository", "d".repeat(40), "nonprod", "sha256:aaa");
        ApprovalValidationResult result = ApprovalValidator.validate(provider, id, wrongCommit, NOW);

        assertEquals(ApprovalValidationReasonCode.COMMIT_SHA_MISMATCH, result.reasonCode());
    }

    // 8. environment mismatch fails
    @Test
    void environmentMismatchFails() {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String id = producer(repo, new MutableClock(NOW)).issue(baseRequest("sha256:aaa"), APPROVER);

        ApprovalProvider provider = new RepositoryBackedApprovalProvider(repo);
        ExecutionIdentity wrongEnv = new ExecutionIdentity("owner/repository", "c".repeat(40), "production", "sha256:aaa");
        ApprovalValidationResult result = ApprovalValidator.validate(provider, id, wrongEnv, NOW);

        assertEquals(ApprovalValidationReasonCode.ENVIRONMENT_MISMATCH, result.reasonCode());
    }

    // 9. repository mismatch fails
    @Test
    void repositoryMismatchFails() {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String id = producer(repo, new MutableClock(NOW)).issue(baseRequest("sha256:aaa"), APPROVER);

        ApprovalProvider provider = new RepositoryBackedApprovalProvider(repo);
        ExecutionIdentity wrongRepo = new ExecutionIdentity("owner/other-repository", "c".repeat(40), "nonprod", "sha256:aaa");
        ApprovalValidationResult result = ApprovalValidator.validate(provider, id, wrongRepo, NOW);

        assertEquals(ApprovalValidationReasonCode.REPOSITORY_MISMATCH, result.reasonCode());
    }

    // 10. immutable bindings cannot be edited
    @Test
    void authorizationBindingsSurviveTransitionsUnchanged() {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        ApprovalRecordProducer producer = producer(repo, new MutableClock(NOW));
        String id = producer.issue(baseRequest("sha256:aaa"), APPROVER);
        ApprovalRecord before = repo.find(id).orElseThrow();

        producer.revoke(id, APPROVER, "rotated");
        ApprovalRecord after = repo.find(id).orElseThrow();

        assertEquals(before.repository(), after.repository());
        assertEquals(before.commitSha(), after.commitSha());
        assertEquals(before.environment(), after.environment());
        assertEquals(before.planSha256(), after.planSha256());
        assertEquals(before.approvedBy(), after.approvedBy());
        assertEquals(before.approvedAt(), after.approvedAt());
        assertNotEquals(before.status(), after.status());
    }

    @Test
    void approvalRecordHasNoEditOperationOtherThanTransitions() {
        Set<String> recordComponentNames = Arrays.stream(ApprovalRecord.class.getRecordComponents())
                .map(RecordComponent::getName)
                .collect(Collectors.toSet());
        Set<String> nonAccessorMethodNames = Arrays.stream(ApprovalRecord.class.getDeclaredMethods())
                .filter(m -> !m.isSynthetic())
                .map(java.lang.reflect.Method::getName)
                .filter(name -> !recordComponentNames.contains(name))
                .filter(name -> !name.equals("toString") && !name.equals("hashCode") && !name.equals("equals"))
                .collect(Collectors.toSet());
        assertEquals(Set.of("identity", "effectiveStatus", "withRevocation", "withSupersession"), nonAccessorMethodNames);
    }

    // 11. changed plan requires a new approval
    @Test
    void changedPlanRequiresNewApproval() {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        ApprovalRecordProducer producer = producer(repo, new MutableClock(NOW));
        String firstId = producer.issue(baseRequest("sha256:aaa"), APPROVER);
        String secondId = producer.issue(baseRequest("sha256:bbb"), APPROVER);

        assertNotEquals(firstId, secondId, "a different plan hash must produce a distinct approval, never an in-place update");
        assertEquals("sha256:aaa", repo.find(firstId).orElseThrow().planSha256());
        assertEquals("sha256:bbb", repo.find(secondId).orElseThrow().planSha256());
    }

    // 12. revocation preserves audit evidence
    @Test
    void revocationPreservesAuditEvidence() {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        MutableClock clock = new MutableClock(NOW);
        ApprovalRecordProducer producer = producer(repo, clock);
        String id = producer.issue(baseRequest("sha256:aaa"), APPROVER);

        Instant revokedAt = NOW.plus(Duration.ofMinutes(10));
        clock.set(revokedAt);
        producer.revoke(id, APPROVER, "credential compromise suspected");

        ApprovalRecord record = repo.find(id).orElseThrow();
        assertEquals(ApprovalStatus.REVOKED, record.status());
        assertEquals(revokedAt, record.revokedAt());
        assertEquals("platform-admin", record.revokedBy());
        assertEquals("credential compromise suspected", record.revokedReason());
    }

    // 13. supersession preserves old record
    @Test
    void supersessionPreservesOldRecord() {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        MutableClock clock = new MutableClock(NOW);
        ApprovalRecordProducer producer = producer(repo, clock);
        String oldId = producer.issue(baseRequest("sha256:aaa"), APPROVER);

        Instant supersededAt = NOW.plus(Duration.ofMinutes(5));
        clock.set(supersededAt);
        SupersedingIssuanceResult result = producer.issueSuperseding(baseRequest("sha256:bbb"), APPROVER, oldId);

        ApprovalRecord oldRecord = repo.find(oldId).orElseThrow();
        assertEquals(ApprovalStatus.SUPERSEDED, oldRecord.status());
        assertEquals(supersededAt, oldRecord.supersededAt());
        assertEquals(result.newApprovalId(), oldRecord.supersedingApprovalId());
        assertEquals("sha256:bbb", oldRecord.supersedingPlanSha256());
        // the old record itself is not deleted - it is still fully resolvable for audit purposes
        assertEquals("sha256:aaa", oldRecord.planSha256());
    }

    // 14. concurrent conflicting transitions cannot both succeed (exercises ApprovalRepository
    // directly - its CAS semantics are unaffected by this amendment's producer-level changes)
    @Test
    void concurrentConflictingTransitionsCannotBothSucceed() throws InterruptedException {
        for (int iteration = 0; iteration < 20; iteration++) {
            InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
            ApprovalRecordProducer producer = producer(repo, new MutableClock(NOW));
            String id = producer.issue(baseRequest("sha256:aaa-" + iteration), APPROVER);

            ExecutorService pool = Executors.newFixedThreadPool(2);
            CountDownLatch ready = new CountDownLatch(2);
            CountDownLatch go = new CountDownLatch(1);
            AtomicInteger successCount = new AtomicInteger(0);

            Runnable revokeAttempt = () -> {
                ready.countDown();
                awaitUninterruptibly(go);
                if (repo.revoke(id, NOW, "security-lead", "race-test") == TransitionOutcome.SUCCESS) {
                    successCount.incrementAndGet();
                }
            };
            Runnable supersedeAttempt = () -> {
                ready.countDown();
                awaitUninterruptibly(go);
                if (repo.supersede(id, NOW, "approval-other", "sha256:other") == TransitionOutcome.SUCCESS) {
                    successCount.incrementAndGet();
                }
            };

            pool.submit(revokeAttempt);
            pool.submit(supersedeAttempt);
            ready.await();
            go.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));

            assertEquals(1, successCount.get(), "exactly one of the two racing transitions must succeed (iteration " + iteration + ")");
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

    // 15. caller cannot inject approval fields through approvalId
    @Test
    void callerSuppliedIdentityCannotForgeApproval() {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String id = producer(repo, new MutableClock(NOW)).issue(baseRequest("sha256:real"), APPROVER);

        ApprovalProvider provider = new RepositoryBackedApprovalProvider(repo);
        ExecutionIdentity forgedIdentity = new ExecutionIdentity("owner/repository", "c".repeat(40), "nonprod", "sha256:forged-desired-hash");
        ApprovalValidationResult result = ApprovalValidator.validate(provider, id, forgedIdentity, NOW);

        assertFalse(result.isValid());
        assertEquals(ApprovalValidationReasonCode.PLAN_HASH_MISMATCH, result.reasonCode());
        assertEquals("sha256:real", result.resolvedRecord().planSha256());
    }

    @Test
    void approvalProviderResolveHasNoParameterForApprovalAttributes() throws NoSuchMethodException {
        var resolveMethod = ApprovalProvider.class.getDeclaredMethod("resolve", String.class);
        assertEquals(1, resolveMethod.getParameterCount());
        assertEquals(String.class, resolveMethod.getParameterTypes()[0]);
    }

    // required: read-only ApprovalProvider has no revoke/supersede/issue surface
    @Test
    void approvalProviderIsReadOnlyWithNoMutationSurface() {
        java.lang.reflect.Method[] methods = ApprovalProvider.class.getDeclaredMethods();
        assertEquals(1, methods.length, "ApprovalProvider must expose exactly resolve() and nothing else");
        assertEquals("resolve", methods[0].getName());
    }

    @Test
    void approvalAuthorityIsTheOnlyMutatingInterface() {
        Set<String> authorityMethods = Arrays.stream(ApprovalAuthority.class.getDeclaredMethods())
                .map(java.lang.reflect.Method::getName)
                .collect(Collectors.toSet());
        assertEquals(Set.of("issue", "revoke", "issueSuperseding"), authorityMethods);
        assertFalse(ApprovalProvider.class.isAssignableFrom(ApprovalAuthority.class));
        assertFalse(ApprovalAuthority.class.isAssignableFrom(ApprovalProvider.class));
    }

    // required: caller cannot choose approvedAt
    @Test
    void callerCannotChooseApprovedAt() {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        MutableClock clock = new MutableClock(NOW);
        ApprovalRecordProducer producer = producer(repo, clock);

        String id = producer.issue(baseRequest("sha256:aaa"), APPROVER);
        assertEquals(NOW, repo.find(id).orElseThrow().approvedAt());

        // there is no field on ApprovalIssuanceRequest to influence this - only the injected
        // clock, controlled exclusively by the trusted producer, determines it
        Instant later = NOW.plus(Duration.ofDays(1));
        clock.set(later);
        String id2 = producer.issue(baseRequest("sha256:bbb"), APPROVER);
        assertEquals(later, repo.find(id2).orElseThrow().approvedAt());
    }

    @Test
    void approvalIssuanceRequestHasNoApprovedAtOrExpiresAtField() {
        Set<String> componentNames = Arrays.stream(ApprovalIssuanceRequest.class.getRecordComponents())
                .map(RecordComponent::getName)
                .collect(Collectors.toSet());
        assertFalse(componentNames.contains("approvedAt"));
        assertFalse(componentNames.contains("expiresAt"));
        assertFalse(componentNames.contains("approvedBy"));
    }

    // required: caller cannot impersonate approvedBy
    @Test
    void callerCannotImpersonateApprovedBy() {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        ApprovalRecordProducer producer = producer(repo, new MutableClock(NOW));
        TrustedApprovalContext realApprover = new TrustedApprovalContext("platform-admin");

        String id = producer.issue(baseRequest("sha256:aaa"), realApprover);

        assertEquals("platform-admin", repo.find(id).orElseThrow().approvedBy());
    }

    @Test
    void issueSignatureHasNoRawApprovedByStringParameter() throws NoSuchMethodException {
        var m = ApprovalAuthority.class.getDeclaredMethod("issue", ApprovalIssuanceRequest.class, TrustedApprovalContext.class);
        assertEquals(2, m.getParameterCount());
        assertFalse(Arrays.asList(m.getParameterTypes()).contains(String.class),
                "issue() must not accept a bare String approvedBy parameter alongside the request");
    }

    @Test
    void trustedApprovalContextRejectsBlankOrNullPrincipal() {
        assertThrows(IllegalArgumentException.class, () -> new TrustedApprovalContext(""));
        assertThrows(IllegalArgumentException.class, () -> new TrustedApprovalContext(null));
    }

    // required: deterministic injected clock controls issuance/expiry
    @Test
    void injectedClockDeterministicallyControlsIssuanceAndExpiry() {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        MutableClock clock = new MutableClock(NOW);
        ApprovalRecordProducer producer = new ApprovalRecordProducer(repo, clock, ApprovalTtlPolicy.fixed(Duration.ofHours(1)));

        String id = producer.issue(baseRequest("sha256:aaa"), APPROVER);
        ApprovalRecord record = repo.find(id).orElseThrow();
        assertEquals(NOW, record.approvedAt());
        assertEquals(NOW.plus(Duration.ofHours(1)), record.expiresAt());

        ApprovalProvider provider = new RepositoryBackedApprovalProvider(repo);
        assertTrue(ApprovalValidator.validate(provider, id, baseIdentity("sha256:aaa"), NOW.plus(Duration.ofMinutes(59))).isValid());
        assertEquals(ApprovalValidationReasonCode.APPROVAL_EXPIRED,
                ApprovalValidator.validate(provider, id, baseIdentity("sha256:aaa"), NOW.plus(Duration.ofHours(1))).reasonCode());
    }

    @Test
    void fixedTtlPolicyRejectsNonPositiveDuration() {
        assertThrows(IllegalArgumentException.class, () -> ApprovalTtlPolicy.fixed(Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> ApprovalTtlPolicy.fixed(Duration.ofMinutes(-1)));
    }

    @Test
    void approvalRecordRejectsExpiresAtNotAfterApprovedAt() {
        assertThrows(IllegalArgumentException.class, () -> new ApprovalRecord(
                "approval-1", "owner/repository", "c".repeat(40), "nonprod", "sha256:aaa",
                "platform-admin", NOW, NOW, ApprovalStatus.ACTIVE, ApprovalProvenance.NONE,
                null, null, null, null, null, null));
    }

    @Test
    void approvalRecordRejectsExpiredAsPersistedStatus() {
        assertThrows(IllegalArgumentException.class, () -> new ApprovalRecord(
                "approval-1", "owner/repository", "c".repeat(40), "nonprod", "sha256:aaa",
                "platform-admin", NOW, NOW.plus(Duration.ofHours(1)), ApprovalStatus.EXPIRED, ApprovalProvenance.NONE,
                null, null, null, null, null, null));
    }

    @Test
    void duplicateApprovalIdCannotSilentlyOverwrite() {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        ApprovalRecord record = new ApprovalRecord(
                "approval-dup", "owner/repository", "c".repeat(40), "nonprod", "sha256:aaa",
                "platform-admin", NOW, NOW.plus(Duration.ofHours(1)), ApprovalStatus.ACTIVE, ApprovalProvenance.NONE,
                null, null, null, null, null, null);
        repo.create(record);

        assertThrows(IllegalStateException.class, () -> repo.create(record));
    }

    @Test
    void issueSupersedingRefusesUnrelatedRepositoryOrEnvironment() {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        ApprovalRecordProducer producer = producer(repo, new MutableClock(NOW));
        String oldId = producer.issue(baseRequest("sha256:aaa"), APPROVER);

        ApprovalIssuanceRequest unrelatedEnvRequest = new ApprovalIssuanceRequest(
                "owner/repository", "c".repeat(40), "production", "sha256:bbb", ApprovalProvenance.NONE);

        assertThrows(IllegalArgumentException.class, () -> producer.issueSuperseding(unrelatedEnvRequest, APPROVER, oldId));
        assertEquals(ApprovalStatus.ACTIVE, repo.find(oldId).orElseThrow().status());
    }

    @Test
    void issueSupersedingStillIssuesNewApprovalWhenPriorAlreadyInactive() {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        ApprovalRecordProducer producer = producer(repo, new MutableClock(NOW));
        String oldId = producer.issue(baseRequest("sha256:aaa"), APPROVER);
        producer.revoke(oldId, APPROVER, "unrelated revocation");

        SupersedingIssuanceResult result = producer.issueSuperseding(baseRequest("sha256:bbb"), APPROVER, oldId);

        assertEquals(TransitionOutcome.ALREADY_TRANSITIONED, result.priorApprovalTransition());
        assertNotNull(result.newApprovalId());
        ApprovalProvider provider = new RepositoryBackedApprovalProvider(repo);
        assertTrue(ApprovalValidator.validate(provider, result.newApprovalId(), baseIdentity("sha256:bbb"), NOW.plus(Duration.ofMinutes(2))).isValid());
    }

    @Test
    void effectiveStatusIsActiveBeforeExpiryAndExpiredAfter() {
        ApprovalRecord record = new ApprovalRecord(
                "approval-1", "owner/repository", "c".repeat(40), "nonprod", "sha256:aaa",
                "platform-admin", NOW, NOW.plus(Duration.ofHours(1)), ApprovalStatus.ACTIVE, ApprovalProvenance.NONE,
                null, null, null, null, null, null);

        assertEquals(ApprovalStatus.ACTIVE, record.effectiveStatus(NOW.plus(Duration.ofMinutes(30))));
        assertEquals(ApprovalStatus.EXPIRED, record.effectiveStatus(NOW.plus(Duration.ofHours(2))));
        ApprovalRecord revoked = record.withRevocation(NOW.plus(Duration.ofMinutes(5)), "security-lead", "reason");
        assertEquals(ApprovalStatus.REVOKED, revoked.effectiveStatus(NOW.plus(Duration.ofHours(2))));
    }
}
