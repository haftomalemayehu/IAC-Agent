package com.iacagent.iacagent.runner;

import com.iacagent.iacagent.approval.ApprovalIssuanceRequest;
import com.iacagent.iacagent.approval.ApprovalProvenance;
import com.iacagent.iacagent.approval.ApprovalProvider;
import com.iacagent.iacagent.approval.ApprovalRecordProducer;
import com.iacagent.iacagent.approval.ApprovalTtlPolicy;
import com.iacagent.iacagent.approval.InMemoryApprovalRepository;
import com.iacagent.iacagent.approval.RepositoryBackedApprovalProvider;
import com.iacagent.iacagent.approval.TrustedApprovalContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 2B-2 hardening tests: durable runner ledger (in-memory domain proof; restart/concurrency
 * proof against the real JDBC backend lives in {@code runner.jdbc.Phase2b2JdbcTests}), verifiable
 * host-attested runner identity, workspace/artifact isolation hardening beyond Phase 2B-1, and the
 * bounded process-environment contract. Phase 2B-1's own suite ({@link Phase2b1Tests}) is left
 * intact and still passes unmodified except where Phase 2B-2 behavior (ledger-backed claim,
 * cleanup-after-record) required updating a test's expectations to match - see that file's comments.
 */
class Phase2b2Tests {

    private static final Instant NOW = Instant.parse("2026-09-10T00:00:00Z");
    private static final String REPOSITORY = "owner/repository";
    private static final String COMMIT_SHA = "c".repeat(40);
    private static final String ENVIRONMENT = "nonprod";
    private static final String TERRAFORM_VERSION = "1.6.6";
    private static final String PROVIDER_LOCK_HASH = "sha256:lock-abc";
    private static final byte[] PLAN_BYTES = "fake-plan-bytes".getBytes(StandardCharsets.UTF_8);
    private static final String PLAN_SHA256 = sha256Hex(PLAN_BYTES);
    private static final Set<String> ALLOWED_RUNNER_CLASSES = Set.of("host-attested-test-runner");

    private static final class MutableClock extends Clock {
        private Instant instant;

        MutableClock(Instant initial) {
            this.instant = initial;
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

    private static String sha256Hex(byte[] content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(content));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private StoredArtifact validArtifact(String artifactId) {
        return new StoredArtifact(artifactId, PLAN_BYTES, PLAN_BYTES.length, PLAN_SHA256, new ArtifactProvenance("test-fixture"));
    }

    private String issueValidApproval(InMemoryApprovalRepository repo, String planSha) {
        ApprovalRecordProducer producer = new ApprovalRecordProducer(repo, new MutableClock(NOW), ApprovalTtlPolicy.fixed(Duration.ofHours(4)));
        ApprovalIssuanceRequest request = new ApprovalIssuanceRequest(REPOSITORY, COMMIT_SHA, ENVIRONMENT, planSha, ApprovalProvenance.NONE);
        return producer.issue(request, new TrustedApprovalContext("platform-admin"));
    }

    private RunnerRequest baseRequest(String requestId, String artifactId, String approvalId) {
        return new RunnerRequest(requestId, REPOSITORY, COMMIT_SHA, ENVIRONMENT, artifactId, PLAN_SHA256,
                TERRAFORM_VERSION, PROVIDER_LOCK_HASH, approvalId, RunnerOperation.PREPARE_EXECUTION);
    }

    private void writeIdentityFile(Path file, String runnerId, String runnerClass, boolean trusted, String... environmentScope) throws IOException {
        String scopeJson = String.join(",", java.util.Arrays.stream(environmentScope).map(s -> "\"" + s + "\"").toList());
        String json = """
                {"runnerId":"%s","runnerClass":"%s","trusted":%s,"environmentScope":[%s]}
                """.formatted(runnerId, runnerClass, trusted, scopeJson);
        Files.writeString(file, json);
    }

    private ControlledRunner runnerWithIdentityFile(Path root, Path identityFile, InMemoryApprovalRepository repo, InMemoryRunnerArtifactStore artifactStore) {
        return new ControlledRunner(
                new HostAttestedRunnerIdentityProvider(identityFile, identityFile.getParent(), List.of(root)),
                ALLOWED_RUNNER_CLASSES,
                new RepositoryBackedApprovalProvider(repo),
                artifactStore,
                new StaticRunnerToolchainContext(TERRAFORM_VERSION, PROVIDER_LOCK_HASH),
                new RunnerWorkspaceManager(root),
                new InMemoryRunnerLedgerRepository(),
                new MutableClock(NOW)
        );
    }

    // ===================== Durable ledger (domain-level, in-memory proof) =====================

    // Exactly one concurrent claimant wins for a previously unseen id.
    @Test
    void claimIsExclusiveAcrossConcurrentCallersForPreviouslyUnseenId() throws InterruptedException {
        InMemoryRunnerLedgerRepository ledger = new InMemoryRunnerLedgerRepository();
        RunnerRequest request = baseRequest("req-race", "artifact-1", "approval-1");

        int threadCount = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        CountDownLatch ready = new CountDownLatch(threadCount);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger claimedCount = new AtomicInteger(0);
        AtomicInteger incompleteCount = new AtomicInteger(0);

        for (int i = 0; i < threadCount; i++) {
            pool.submit(() -> {
                ready.countDown();
                awaitUninterruptibly(go);
                RunnerClaimOutcome outcome = ledger.claim(request, NOW);
                if (outcome == RunnerClaimOutcome.CLAIMED) claimedCount.incrementAndGet();
                if (outcome == RunnerClaimOutcome.INCOMPLETE_PRIOR_CLAIM) incompleteCount.incrementAndGet();
            });
        }
        ready.await();
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

        assertEquals(1, claimedCount.get(), "exactly one caller may claim a previously unseen id");
        assertEquals(threadCount - 1, incompleteCount.get());
    }

    // Concurrent claims under DIFFERENT fingerprints for the same id must not corrupt each other:
    // the single winner's fingerprint remains authoritative, every other caller sees a mismatch.
    @Test
    void concurrentClaimsWithDifferentFingerprintsDoNotOverwriteTheWinner() throws InterruptedException {
        InMemoryRunnerLedgerRepository ledger = new InMemoryRunnerLedgerRepository();
        RunnerRequest requestA = baseRequest("req-race-2", "artifact-A", "approval-A");
        RunnerRequest requestB = baseRequest("req-race-2", "artifact-B", "approval-B");

        ExecutorService pool = Executors.newFixedThreadPool(2);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch go = new CountDownLatch(1);
        AtomicReference<RunnerClaimOutcome> outcomeA = new AtomicReference<>();
        AtomicReference<RunnerClaimOutcome> outcomeB = new AtomicReference<>();
        pool.submit(() -> {
            ready.countDown();
            awaitUninterruptibly(go);
            outcomeA.set(ledger.claim(requestA, NOW));
        });
        pool.submit(() -> {
            ready.countDown();
            awaitUninterruptibly(go);
            outcomeB.set(ledger.claim(requestB, NOW));
        });
        ready.await();
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

        boolean exactlyOneClaimed = (outcomeA.get() == RunnerClaimOutcome.CLAIMED) ^ (outcomeB.get() == RunnerClaimOutcome.CLAIMED);
        assertTrue(exactlyOneClaimed, "exactly one of two differently-fingerprinted racers may claim the shared id");
        RunnerClaimOutcome loser = outcomeA.get() == RunnerClaimOutcome.CLAIMED ? outcomeB.get() : outcomeA.get();
        assertEquals(RunnerClaimOutcome.FINGERPRINT_MISMATCH, loser);
    }

    @Test
    void recordTerminalEvidenceForAnUnclaimedIdThrows() {
        InMemoryRunnerLedgerRepository ledger = new InMemoryRunnerLedgerRepository();
        RunnerEvidence evidence = evidenceFor(baseRequest("req-unclaimed", "artifact-1", "approval-1"), RunnerState.READY_FOR_FUTURE_EXECUTION, List.of());
        assertThrows(IllegalStateException.class, () -> ledger.recordTerminalEvidence(evidence));
    }

    @Test
    void recordTerminalEvidenceTwiceForTheSameIdThrowsOnTheSecondAttempt() {
        InMemoryRunnerLedgerRepository ledger = new InMemoryRunnerLedgerRepository();
        RunnerRequest request = baseRequest("req-double-record", "artifact-1", "approval-1");
        ledger.claim(request, NOW);
        RunnerEvidence evidence = evidenceFor(request, RunnerState.READY_FOR_FUTURE_EXECUTION, List.of());
        ledger.recordTerminalEvidence(evidence);
        assertThrows(IllegalStateException.class, () -> ledger.recordTerminalEvidence(evidence),
                "a COMPLETED row's evidence must never be rewritable, even with identical content");
    }

    @Test
    void findHistoricalEvidenceReturnsEmptyForAClaimedButNotYetCompletedId() {
        InMemoryRunnerLedgerRepository ledger = new InMemoryRunnerLedgerRepository();
        RunnerRequest request = baseRequest("req-claimed-only", "artifact-1", "approval-1");
        ledger.claim(request, NOW);
        assertTrue(ledger.findHistoricalEvidence("req-claimed-only").isEmpty(),
                "a CLAIMED-but-incomplete row has no terminal evidence to report yet");
    }

    @Test
    void findHistoricalEvidenceReturnsEmptyForAnUnknownId() {
        InMemoryRunnerLedgerRepository ledger = new InMemoryRunnerLedgerRepository();
        assertTrue(ledger.findHistoricalEvidence("never-seen").isEmpty());
    }

    // No general update/delete surface exists on the ledger contract.
    @Test
    void runnerLedgerRepositoryExposesOnlyClaimRecordAndFind() {
        Set<String> methodNames = java.util.Arrays.stream(RunnerLedgerRepository.class.getDeclaredMethods())
                .map(Method::getName)
                .collect(Collectors.toSet());
        assertEquals(Set.of("claim", "recordTerminalEvidence", "findHistoricalEvidence"), methodNames);
    }

    private RunnerEvidence evidenceFor(RunnerRequest request, RunnerState finalState, List<RunnerReasonCode> reasonCodes) {
        return new RunnerEvidence(
                request.runnerRequestId(), "runner-1", "host-attested-test-runner", Set.of(ENVIRONMENT),
                request.requestedOperation(), request.repository(), request.commitSha(), request.environment(),
                request.planArtifactId(), request.planSha256(), request.planSha256(),
                request.terraformVersion(), request.terraformVersion(), request.providerLockHash(), request.providerLockHash(),
                request.approvalId(), com.iacagent.iacagent.approval.ApprovalValidationReasonCode.VALID,
                finalState, reasonCodes, NOW, NOW.plusSeconds(1));
    }

    // ===================== Canonical request fingerprint (unambiguous encoding) =====================

    @Test
    void fingerprintIsDeterministicForTheSameLogicalRequest() {
        RunnerRequest a = baseRequest("req-det", "artifact-1", "approval-1");
        RunnerRequest b = new RunnerRequest("req-det", REPOSITORY, COMMIT_SHA, ENVIRONMENT, "artifact-1", PLAN_SHA256,
                TERRAFORM_VERSION, PROVIDER_LOCK_HASH, "approval-1", RunnerOperation.PREPARE_EXECUTION);

        assertEquals(a.fingerprintSha256(), b.fingerprintSha256(),
                "two separately-constructed but field-for-field-identical requests must fingerprint identically");
    }

    @Test
    void fingerprintDiffersWhenAnySingleFieldDiffers() {
        RunnerRequest base = baseRequest("req-diff", "artifact-1", "approval-1");
        RunnerRequest differentArtifact = baseRequest("req-diff", "artifact-2", "approval-1");
        RunnerRequest differentApproval = baseRequest("req-diff", "artifact-1", "approval-2");
        RunnerRequest differentOperation = new RunnerRequest("req-diff", REPOSITORY, COMMIT_SHA, ENVIRONMENT, "artifact-1",
                PLAN_SHA256, TERRAFORM_VERSION, PROVIDER_LOCK_HASH, "approval-1", RunnerOperation.VERIFY_ARTIFACT);

        assertNotEquals(base.fingerprintSha256(), differentArtifact.fingerprintSha256());
        assertNotEquals(base.fingerprintSha256(), differentApproval.fingerprintSha256());
        assertNotEquals(base.fingerprintSha256(), differentOperation.fingerprintSha256());
    }

    // The adversarial case a delimiter-joined (e.g. single-NUL-separated) encoding cannot rule out:
    // two differently-partitioned field tuples that concatenate to the exact same delimited string.
    // repository="a", commitSha="b\0c"        -> NUL-joined: "a" + \0 + "b\0c" + \0 + ...   = "a\0b\0c\0..."
    // repository="a\0b", commitSha="c"        -> NUL-joined: "a\0b" + \0 + "c" + \0 + ...   = "a\0b\0c\0..."
    // Both are valid (non-blank) strings, so a delimiter-based fingerprint would collide here even
    // though these are two distinct field tuples. The length-prefixed encoding must NOT collide.
    @Test
    void differentlyPartitionedFieldsThatWouldCollideUnderNulDelimitedJoiningProduceDifferentFingerprints() {
        String nul = String.valueOf((char) 0);
        RunnerRequest partitionA = new RunnerRequest("req-partition", "a", "b" + nul + "c", ENVIRONMENT,
                "artifact-1", PLAN_SHA256, TERRAFORM_VERSION, PROVIDER_LOCK_HASH, "approval-1", RunnerOperation.PREPARE_EXECUTION);
        RunnerRequest partitionB = new RunnerRequest("req-partition", "a" + nul + "b", "c", ENVIRONMENT,
                "artifact-1", PLAN_SHA256, TERRAFORM_VERSION, PROVIDER_LOCK_HASH, "approval-1", RunnerOperation.PREPARE_EXECUTION);

        // Sanity: confirm these two really would have collided under naive NUL-delimited joining -
        // otherwise this test would not actually be exercising the adversarial case it claims to.
        String naiveJoinA = String.join(nul, partitionA.repository(), partitionA.commitSha(), partitionA.environment(),
                partitionA.planArtifactId(), partitionA.planSha256(), partitionA.terraformVersion(),
                partitionA.providerLockHash(), partitionA.approvalId(), partitionA.requestedOperation().name());
        String naiveJoinB = String.join(nul, partitionB.repository(), partitionB.commitSha(), partitionB.environment(),
                partitionB.planArtifactId(), partitionB.planSha256(), partitionB.terraformVersion(),
                partitionB.providerLockHash(), partitionB.approvalId(), partitionB.requestedOperation().name());
        assertEquals(naiveJoinA, naiveJoinB, "test setup error: these two field tuples must naively NUL-join to the same string");

        assertNotEquals(partitionA.fingerprintSha256(), partitionB.fingerprintSha256(),
                "the canonical length-prefixed encoding must distinguish field tuples a NUL-delimited join cannot");
    }

    // Same shape of adversarial ambiguity, using the more "ordinary" delimiter candidates a reviewer
    // might otherwise reach for (comma, pipe, newline) instead of NUL - the length-prefixed encoding
    // must not be vulnerable to any of them, precisely because it never treats any byte as special.
    @Test
    void differentlyPartitionedFieldsWithOrdinaryDelimiterCharactersDoNotCollide() {
        RunnerRequest commaPartitionA = new RunnerRequest("req-comma", "a", "b,c", ENVIRONMENT,
                "artifact-1", PLAN_SHA256, TERRAFORM_VERSION, PROVIDER_LOCK_HASH, "approval-1", RunnerOperation.PREPARE_EXECUTION);
        RunnerRequest commaPartitionB = new RunnerRequest("req-comma", "a,b", "c", ENVIRONMENT,
                "artifact-1", PLAN_SHA256, TERRAFORM_VERSION, PROVIDER_LOCK_HASH, "approval-1", RunnerOperation.PREPARE_EXECUTION);
        assertNotEquals(commaPartitionA.fingerprintSha256(), commaPartitionB.fingerprintSha256());

        RunnerRequest pipePartitionA = new RunnerRequest("req-pipe", "a", "b|c", ENVIRONMENT,
                "artifact-1", PLAN_SHA256, TERRAFORM_VERSION, PROVIDER_LOCK_HASH, "approval-1", RunnerOperation.PREPARE_EXECUTION);
        RunnerRequest pipePartitionB = new RunnerRequest("req-pipe", "a|b", "c", ENVIRONMENT,
                "artifact-1", PLAN_SHA256, TERRAFORM_VERSION, PROVIDER_LOCK_HASH, "approval-1", RunnerOperation.PREPARE_EXECUTION);
        assertNotEquals(pipePartitionA.fingerprintSha256(), pipePartitionB.fingerprintSha256());

        RunnerRequest newlinePartitionA = new RunnerRequest("req-newline", "a", "b\nc", ENVIRONMENT,
                "artifact-1", PLAN_SHA256, TERRAFORM_VERSION, PROVIDER_LOCK_HASH, "approval-1", RunnerOperation.PREPARE_EXECUTION);
        RunnerRequest newlinePartitionB = new RunnerRequest("req-newline", "a\nb", "c", ENVIRONMENT,
                "artifact-1", PLAN_SHA256, TERRAFORM_VERSION, PROVIDER_LOCK_HASH, "approval-1", RunnerOperation.PREPARE_EXECUTION);
        assertNotEquals(newlinePartitionA.fingerprintSha256(), newlinePartitionB.fingerprintSha256());
    }

    // ===================== Verifiable host-attested identity =====================

    @Test
    void hostAttestedIdentityProviderReadsIdentityFromItsConfiguredFile(@TempDir Path dir, @TempDir Path unrelatedWorkspaceRoot) throws IOException {
        Path identityFile = dir.resolve("identity.json");
        writeIdentityFile(identityFile, "runner-42", "host-attested-test-runner", true, "nonprod", "staging");

        var identity = new HostAttestedRunnerIdentityProvider(identityFile, dir, List.of(unrelatedWorkspaceRoot)).currentIdentity();

        assertTrue(identity.isPresent());
        assertEquals("runner-42", identity.get().runnerId());
        assertEquals("host-attested-test-runner", identity.get().runnerClass());
        assertTrue(identity.get().trusted());
        assertEquals(Set.of("nonprod", "staging"), identity.get().environmentScope());
    }

    @Test
    void hostAttestedIdentityProviderReturnsEmptyWhenFileIsMissing(@TempDir Path dir, @TempDir Path unrelatedWorkspaceRoot) {
        Path missing = dir.resolve("does-not-exist.json");
        assertTrue(new HostAttestedRunnerIdentityProvider(missing, dir, List.of(unrelatedWorkspaceRoot)).currentIdentity().isEmpty());
    }

    @Test
    void hostAttestedIdentityProviderReturnsEmptyOnMalformedJson(@TempDir Path dir, @TempDir Path unrelatedWorkspaceRoot) throws IOException {
        Path identityFile = dir.resolve("identity.json");
        Files.writeString(identityFile, "{ this is not valid json");
        assertTrue(new HostAttestedRunnerIdentityProvider(identityFile, dir, List.of(unrelatedWorkspaceRoot)).currentIdentity().isEmpty());
    }

    @Test
    void hostAttestedIdentityProviderReturnsEmptyWhenRunnerClassFieldIsMissing(@TempDir Path dir, @TempDir Path unrelatedWorkspaceRoot) throws IOException {
        Path identityFile = dir.resolve("identity.json");
        Files.writeString(identityFile, "{\"runnerId\":\"runner-1\",\"trusted\":true,\"environmentScope\":[\"nonprod\"]}");
        assertTrue(new HostAttestedRunnerIdentityProvider(identityFile, dir, List.of(unrelatedWorkspaceRoot)).currentIdentity().isEmpty());
    }

    // The constructor rejects an identityFile that does not even textually resolve under the
    // trusted identity root - a workspace root passed as trustedIdentityRoot by mistake would be
    // caught here, at construction, before ever reaching a per-call check.
    @Test
    void constructorRejectsAnIdentityFileNotUnderTheTrustedIdentityRoot(@TempDir Path trustedRoot, @TempDir Path elsewhere) throws IOException {
        Path identityFileOutsideTrustedRoot = elsewhere.resolve("identity.json");
        writeIdentityFile(identityFileOutsideTrustedRoot, "runner-1", "host-attested-test-runner", true, ENVIRONMENT);

        assertThrows(IllegalArgumentException.class,
                () -> new HostAttestedRunnerIdentityProvider(identityFileOutsideTrustedRoot, trustedRoot, List.of()),
                "an identity file outside the trusted identity root must be rejected at construction");
    }

    // The constructor rejects a configuration where the trusted root itself resolves underneath an
    // untrusted root - a direct contradiction that should fail loudly, not silently.
    @Test
    void constructorRejectsATrustedRootThatResolvesUnderAnUntrustedRoot(@TempDir Path untrustedRoot) {
        Path trustedRootInsideUntrusted = untrustedRoot.resolve("trusted-looking-subdir");
        assertThrows(IllegalArgumentException.class,
                () -> {
                    Files.createDirectory(trustedRootInsideUntrusted);
                    new HostAttestedRunnerIdentityProvider(
                            trustedRootInsideUntrusted.resolve("identity.json"), trustedRootInsideUntrusted, List.of(untrustedRoot));
                });
    }

    // Identity under a repository-checkout root - nested inside the trusted root, but explicitly
    // named as an untrusted root - is rejected, distinctly from the trusted-root-containment check.
    @Test
    void identityUnderARepositoryCheckoutRootIsRejected(@TempDir Path trustedRoot) throws IOException {
        Path repositoryRoot = trustedRoot.resolve("repo-checkout");
        Files.createDirectory(repositoryRoot);
        Path identityFile = repositoryRoot.resolve("identity.json");
        writeIdentityFile(identityFile, "runner-attacker", "host-attested-test-runner", true, ENVIRONMENT);

        HostAttestedRunnerIdentityProvider provider =
                new HostAttestedRunnerIdentityProvider(identityFile, trustedRoot, List.of(repositoryRoot));

        assertTrue(provider.currentIdentity().isEmpty(), "an identity file physically inside the repository-checkout root must be rejected");
    }

    // Same shape, for the runner's own workspace root - nested inside the trusted root, but
    // explicitly named as an untrusted root.
    @Test
    void identityUnderTheWorkspaceRootIsRejected(@TempDir Path trustedRoot) throws IOException {
        Path workspaceRoot = trustedRoot.resolve("workspace");
        Files.createDirectory(workspaceRoot);
        Path identityFile = workspaceRoot.resolve("identity.json");
        writeIdentityFile(identityFile, "runner-attacker", "host-attested-test-runner", true, ENVIRONMENT);

        HostAttestedRunnerIdentityProvider provider =
                new HostAttestedRunnerIdentityProvider(identityFile, trustedRoot, List.of(workspaceRoot));

        assertTrue(provider.currentIdentity().isEmpty(), "an identity file physically inside the workspace root must be rejected");
    }

    // A genuinely safe regular file, directly under the trusted root and under no untrusted root,
    // succeeds - the positive counterpart to the two rejection tests above.
    @Test
    void safeRegularIdentityFileBelowTrustedRootSucceeds(@TempDir Path trustedRoot, @TempDir Path repositoryRoot, @TempDir Path workspaceRoot) throws IOException {
        Path identityFile = trustedRoot.resolve("identity.json");
        writeIdentityFile(identityFile, "runner-1", "host-attested-test-runner", true, ENVIRONMENT);

        HostAttestedRunnerIdentityProvider provider =
                new HostAttestedRunnerIdentityProvider(identityFile, trustedRoot, List.of(repositoryRoot, workspaceRoot));

        var identity = provider.currentIdentity();
        assertTrue(identity.isPresent());
        assertEquals("runner-1", identity.get().runnerId());
    }

    // A symlink at the identity file's exact path is rejected outright, never followed - regardless
    // of whether the symlink's target would itself have been a perfectly valid identity file.
    @Test
    void symlinkAtTheIdentityFilePathIsRejectedRatherThanFollowed(@TempDir Path dir, @TempDir Path unrelatedWorkspaceRoot) throws IOException {
        Path realTarget = dir.resolve("real-identity.json");
        writeIdentityFile(realTarget, "runner-1", "host-attested-test-runner", true, ENVIRONMENT);
        Path symlinkIdentityFile = dir.resolve("identity-via-symlink.json");
        try {
            Files.createSymbolicLink(symlinkIdentityFile, realTarget);
        } catch (UnsupportedOperationException | IOException e) {
            return; // platform/filesystem does not support symlinks - best-effort, matches Phase 2A precedent
        }

        var identity = new HostAttestedRunnerIdentityProvider(symlinkIdentityFile, dir, List.of(unrelatedWorkspaceRoot)).currentIdentity();

        assertTrue(identity.isEmpty(), "a symlinked identity path must be rejected even though its target is a valid identity file");
    }

    // The harder case: the leaf path itself is an ordinary regular file, but an ANCESTOR directory
    // component between the trusted root and that file is a symlink into an untrusted (repository)
    // root - Files.isRegularFile(leaf, NOFOLLOW_LINKS) alone would never notice this, since the leaf
    // itself is not a symlink. Only resolving the full real path and comparing it against the
    // trusted/untrusted roots catches it.
    @Test
    void ancestorDirectorySymlinkRedirectionIntoAnUntrustedRootIsRejected(@TempDir Path trustedRoot, @TempDir Path repositoryRoot) throws IOException {
        // "subdir" deliberately does not exist yet at construction time - the eager construction-time
        // check (which would otherwise itself, correctly, reject a parent that ALREADY resolves into
        // an untrusted root) has nothing to follow yet, so construction succeeds here on the strength
        // of the still-legitimate textual path alone. The symlink is planted only afterwards, so this
        // test specifically exercises the PER-CALL real-path check, not the constructor's eager one.
        Path subdir = trustedRoot.resolve("subdir");
        Path identityFile = subdir.resolve("identity.json"); // trusted-looking path: trustedRoot/subdir/identity.json

        Path redirectedTarget = repositoryRoot.resolve("attacker-controlled");
        Files.createDirectory(redirectedTarget);
        writeIdentityFile(redirectedTarget.resolve("identity.json"), "runner-attacker", "host-attested-test-runner", true, ENVIRONMENT);

        HostAttestedRunnerIdentityProvider provider =
                new HostAttestedRunnerIdentityProvider(identityFile, trustedRoot, List.of(repositoryRoot));

        try {
            Files.createSymbolicLink(subdir, redirectedTarget); // trustedRoot/subdir now POINTS INTO repositoryRoot
        } catch (UnsupportedOperationException | IOException e) {
            return; // platform/filesystem does not support symlinks - best-effort, matches Phase 2A precedent
        }

        assertTrue(provider.currentIdentity().isEmpty(),
                "identity.json's leaf path is an ordinary regular file, but its real location - reached through the "
                        + "now-symlinked ancestor directory - is inside the untrusted repository root, and must be rejected");
    }

    // A safe arrangement that resolved identity correctly on the first call must NOT continue being
    // trusted once an ancestor directory is later replaced with a symlink into untrusted territory -
    // this is the "replacement/tampering after a valid first read" case, via the ancestor-redirection
    // mechanism rather than a direct leaf-symlink swap (already covered above).
    @Test
    void ancestorDirectoryReplacedWithASymlinkAfterAValidFirstReadBlocksOnTheNextRead(@TempDir Path trustedRoot, @TempDir Path repositoryRoot) throws IOException {
        Path subdir = trustedRoot.resolve("subdir");
        Files.createDirectory(subdir);
        Path identityFile = subdir.resolve("identity.json");
        writeIdentityFile(identityFile, "runner-1", "host-attested-test-runner", true, ENVIRONMENT);

        HostAttestedRunnerIdentityProvider provider =
                new HostAttestedRunnerIdentityProvider(identityFile, trustedRoot, List.of(repositoryRoot));
        assertTrue(provider.currentIdentity().isPresent(), "identity must resolve correctly before the ancestor is tampered with");

        Path redirectedTarget = repositoryRoot.resolve("attacker-controlled");
        Files.createDirectory(redirectedTarget);
        writeIdentityFile(redirectedTarget.resolve("identity.json"), "runner-attacker", "host-attested-test-runner", true, ENVIRONMENT);

        deleteRecursively(subdir);
        try {
            Files.createSymbolicLink(subdir, redirectedTarget);
        } catch (UnsupportedOperationException | IOException e) {
            return; // platform/filesystem does not support symlinks - best-effort, matches Phase 2A precedent
        }

        assertTrue(provider.currentIdentity().isEmpty(),
                "a previously-valid path arrangement, once an ancestor directory is redirected into an untrusted root, "
                        + "must block on the very next read - never continue trusting the identity resolved before the change");
    }

    private static void deleteRecursively(Path path) throws IOException {
        if (!Files.exists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        try (var walk = Files.walk(path)) {
            walk.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.delete(p);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            });
        }
    }

    // Tampering (replacing a previously-valid regular file with a symlink) must block on the very
    // next call, never continue to trust the identity resolved before the replacement.
    @Test
    void replacingTheIdentityFileWithASymlinkProducesBlockedRatherThanCachedTrust(@TempDir Path dir, @TempDir Path unrelatedWorkspaceRoot) throws IOException {
        Path identityFile = dir.resolve("identity.json");
        writeIdentityFile(identityFile, "runner-1", "host-attested-test-runner", true, ENVIRONMENT);
        HostAttestedRunnerIdentityProvider provider = new HostAttestedRunnerIdentityProvider(identityFile, dir, List.of(unrelatedWorkspaceRoot));
        assertTrue(provider.currentIdentity().isPresent(), "identity must be readable before tampering");

        Path decoyTarget = dir.resolve("decoy-identity.json");
        writeIdentityFile(decoyTarget, "runner-attacker", "host-attested-test-runner", true, ENVIRONMENT);
        Files.delete(identityFile);
        try {
            Files.createSymbolicLink(identityFile, decoyTarget);
        } catch (UnsupportedOperationException | IOException e) {
            return; // platform/filesystem does not support symlinks - best-effort, matches Phase 2A precedent
        }

        assertTrue(provider.currentIdentity().isEmpty(),
                "a regular file replaced by a symlink must block immediately, never continue trusting the previously-resolved identity");
    }

    // No caching: revocation/rotation of the identity file takes effect on the very next call,
    // never requiring a restart or explicit invalidation.
    @Test
    void hostAttestedIdentityProviderReflectsFileChangesOnTheNextCallWithoutCaching(@TempDir Path dir, @TempDir Path unrelatedWorkspaceRoot) throws IOException {
        Path identityFile = dir.resolve("identity.json");
        writeIdentityFile(identityFile, "runner-1", "host-attested-test-runner", true, "nonprod");
        HostAttestedRunnerIdentityProvider provider = new HostAttestedRunnerIdentityProvider(identityFile, dir, List.of(unrelatedWorkspaceRoot));

        assertTrue(provider.currentIdentity().isPresent(), "identity must be readable before revocation");

        Files.delete(identityFile); // simulate revocation: the host removes the attestation source

        assertTrue(provider.currentIdentity().isEmpty(), "identity must become unavailable immediately, with no stale cached value");
    }

    // A caller's request content cannot influence which identity is resolved - the SAME identity
    // file backs two requests whose every other field differs.
    @Test
    void requestContentCannotInfluenceResolvedIdentity(@TempDir Path dir, @TempDir Path unrelatedWorkspaceRoot) throws IOException {
        Path identityFile = dir.resolve("identity.json");
        writeIdentityFile(identityFile, "runner-fixed", "host-attested-test-runner", true, ENVIRONMENT);
        HostAttestedRunnerIdentityProvider provider = new HostAttestedRunnerIdentityProvider(identityFile, dir, List.of(unrelatedWorkspaceRoot));

        RunnerRequest requestA = baseRequest("req-identity-a", "artifact-a", "approval-a");
        RunnerRequest requestB = new RunnerRequest("req-identity-b", "different/repository", "d".repeat(40), "production",
                "artifact-b", "sha256:different", "9.9.9", "sha256:different-lock", "approval-b", RunnerOperation.VERIFY_ARTIFACT);

        var identityWhileHandlingA = provider.currentIdentity().orElseThrow();
        var identityWhileHandlingB = provider.currentIdentity().orElseThrow();

        assertEquals(identityWhileHandlingA, identityWhileHandlingB,
                "the identity provider takes no request parameter at all - it cannot see requestA/requestB to be influenced by them");
        // RunnerIdentityProvider#currentIdentity has zero parameters - this is a structural
        // guarantee, not merely an observation about this test's two calls.
        assertEquals(0, RunnerIdentityProvider.class.getDeclaredMethods()[0].getParameterCount());
    }

    @Test
    void missingHostAttestedIdentityBlocksControlledRunnerExecution(@TempDir Path root, @TempDir Path identityDir) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String approvalId = issueValidApproval(repo, PLAN_SHA256);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(validArtifact("artifact-1"));
        Path missingIdentityFile = identityDir.resolve("absent.json");

        ControlledRunner runner = runnerWithIdentityFile(root, missingIdentityFile, repo, artifactStore);
        RunnerEvidence evidence = runner.execute(baseRequest("req-1", "artifact-1", approvalId));

        assertEquals(RunnerState.BLOCKED, evidence.finalState());
        assertEquals(List.of(RunnerReasonCode.RUNNER_IDENTITY_UNAVAILABLE), evidence.reasonCodes());
        assertNull(evidence.runnerId(), "no identity was ever resolved, so none may appear in evidence");
    }

    @Test
    void runnerClassNotInAllowlistBlocksControlledRunnerExecution(@TempDir Path root, @TempDir Path identityDir) throws IOException {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String approvalId = issueValidApproval(repo, PLAN_SHA256);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(validArtifact("artifact-1"));
        Path identityFile = identityDir.resolve("identity.json");
        writeIdentityFile(identityFile, "runner-1", "some-other-runner-class", true, ENVIRONMENT);

        ControlledRunner runner = runnerWithIdentityFile(root, identityFile, repo, artifactStore);
        RunnerEvidence evidence = runner.execute(baseRequest("req-1", "artifact-1", approvalId));

        assertEquals(RunnerState.BLOCKED, evidence.finalState());
        assertEquals(List.of(RunnerReasonCode.RUNNER_CLASS_NOT_ALLOWED), evidence.reasonCodes());
    }

    @Test
    void environmentScopeMismatchBlocksAndApprovedEnvironmentSucceedsForHostAttestedIdentity(@TempDir Path root, @TempDir Path identityDir) throws IOException {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(validArtifact("artifact-1"));
        Path identityFile = identityDir.resolve("identity.json");
        writeIdentityFile(identityFile, "runner-1", "host-attested-test-runner", true, "production"); // NOT "nonprod"

        ControlledRunner runner = runnerWithIdentityFile(root, identityFile, repo, artifactStore);
        String approvalId = issueValidApproval(repo, PLAN_SHA256);
        RunnerEvidence mismatch = runner.execute(baseRequest("req-mismatch", "artifact-1", approvalId));
        assertEquals(List.of(RunnerReasonCode.RUNNER_ENVIRONMENT_NOT_ALLOWED), mismatch.reasonCodes());

        writeIdentityFile(identityFile, "runner-1", "host-attested-test-runner", true, ENVIRONMENT);
        String approvalId2 = issueValidApproval(repo, PLAN_SHA256);
        RunnerEvidence success = runner.execute(baseRequest("req-success", "artifact-1", approvalId2));
        assertEquals(RunnerState.READY_FOR_FUTURE_EXECUTION, success.finalState());
    }

    // ===================== Workspace / artifact isolation hardening =====================

    @Test
    void symlinkPlantedUnderRootIsRejectedRatherThanFollowedOutsideRoot(@TempDir Path root, @TempDir Path outside) throws IOException {
        RunnerWorkspaceManager manager = new RunnerWorkspaceManager(root);
        String runnerRequestId = "req-symlink-target";
        // Reproduce the manager's own hash-derived directory name so the planted symlink actually
        // sits where the manager would otherwise create the real workspace directory.
        String hashedName = sha256Hex(runnerRequestId.getBytes(StandardCharsets.UTF_8));
        Path plantedSymlink = root.resolve(hashedName);
        try {
            Files.createSymbolicLink(plantedSymlink, outside);
        } catch (UnsupportedOperationException | IOException e) {
            return; // platform/filesystem does not support symlinks - best-effort, matches Phase 2A precedent
        }

        // requireUnderRoot's real-path check throws IllegalStateException directly (Files.createDirectories
        // succeeds without error on a pre-existing symlinked directory, so no IOException is ever raised
        // to be wrapped as RunnerWorkspaceException here) - ControlledRunner's own catch(RuntimeException)
        // around workspace creation covers both, so either exception type blocks correctly in production.
        assertThrows(IllegalStateException.class, () -> manager.createWorkspace(runnerRequestId),
                "a symlink planted at the computed workspace path must be rejected, not silently followed outside root");
        try (var listing = Files.list(outside)) {
            assertEquals(0, listing.count(), "nothing must have been written through the symlink into the outside directory");
        }
    }

    @Test
    void cleanupRejectsAPathOutsideTheConfiguredRoot(@TempDir Path root, @TempDir Path outside) throws IOException {
        RunnerWorkspaceManager manager = new RunnerWorkspaceManager(root);
        Path outsideFile = outside.resolve("innocent-bystander.txt");
        Files.writeString(outsideFile, "do not delete me");

        boolean result = manager.cleanup(outside);

        assertFalse(result, "cleanup of a path outside the configured root must fail, not succeed");
        assertTrue(Files.exists(outsideFile), "an out-of-root cleanup attempt must never delete anything");
    }

    @Test
    void stageArtifactAcceptsNoCallerSuppliedFilenameOrArtifactIdParameter() throws NoSuchMethodException {
        Method stageArtifact = RunnerWorkspaceManager.class.getMethod("stageArtifact", Path.class, String.class, byte[].class);
        // (workspace, sha256Hex, content) only - there is no artifactId/filename parameter through
        // which a caller could choose the staged file's name.
        assertEquals(3, stageArtifact.getParameterCount());
        assertEquals(Path.class, stageArtifact.getParameterTypes()[0]);
        assertEquals(String.class, stageArtifact.getParameterTypes()[1]);
        assertEquals(byte[].class, stageArtifact.getParameterTypes()[2]);
    }

    // ===================== Bounded process-environment contract =====================

    @Test
    void allowlistPolicyBuildsOnlyTheFixedExplicitEntrySet(@TempDir Path workspace) {
        AllowlistProcessEnvironmentPolicy policy = new AllowlistProcessEnvironmentPolicy();
        RunnerRequest request = baseRequest("req-env", "artifact-1", "approval-1");

        ProcessEnvironment environment = policy.buildFor(request, workspace);

        assertEquals(Set.of("TF_IN_AUTOMATION", "TF_INPUT", "HOME", "TMPDIR"), environment.variables().keySet());
        assertEquals("true", environment.variables().get("TF_IN_AUTOMATION"));
        assertEquals("0", environment.variables().get("TF_INPUT"));
    }

    @Test
    void allowlistPolicyNeverSetsPathOrAnyCloudOrVcsCredentialVariable(@TempDir Path workspace) {
        AllowlistProcessEnvironmentPolicy policy = new AllowlistProcessEnvironmentPolicy();
        Map<String, String> variables = policy.buildFor(baseRequest("req-env", "artifact-1", "approval-1"), workspace).variables();

        assertFalse(variables.containsKey("PATH"), "no process may launch with a runner/caller-influenced PATH in Phase 2B-2");
        List<String> forbiddenCredentialLikeNames = List.of(
                "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                "AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS",
                "GITHUB_TOKEN", "GH_TOKEN", "VAULT_TOKEN", "VAULT_ADDR");
        for (String forbidden : forbiddenCredentialLikeNames) {
            assertFalse(variables.containsKey(forbidden), "must not contain " + forbidden);
        }
    }

    // A caller cannot inject arbitrary variables or influence the fixed key set via request
    // content - only HOME/TMPDIR vary, and only with the (runner-controlled) workspace path, never
    // with anything from the request.
    @Test
    void requestContentCannotInjectOrChangeAnyEnvironmentVariable(@TempDir Path workspace) {
        AllowlistProcessEnvironmentPolicy policy = new AllowlistProcessEnvironmentPolicy();
        RunnerRequest benign = baseRequest("req-benign", "artifact-1", "approval-1");
        RunnerRequest hostile = new RunnerRequest("req-hostile", "PATH=/evil:$PATH", "d".repeat(40), "AWS_ACCESS_KEY_ID=hijacked",
                "../../etc/passwd", "sha256:hostile", "0.0.0-evil", "sha256:hostile-lock", "approval-hostile", RunnerOperation.PREPARE_EXECUTION);

        ProcessEnvironment fromBenign = policy.buildFor(benign, workspace);
        ProcessEnvironment fromHostile = policy.buildFor(hostile, workspace);

        assertEquals(fromBenign, fromHostile, "environment output must depend only on (workspace), never on request field content");
    }

    @Test
    void environmentHomeAndTmpdirRemainUnderTheGivenWorkspace(@TempDir Path workspace) {
        AllowlistProcessEnvironmentPolicy policy = new AllowlistProcessEnvironmentPolicy();
        ProcessEnvironment environment = policy.buildFor(baseRequest("req-env", "artifact-1", "approval-1"), workspace);

        assertTrue(Path.of(environment.variables().get("HOME")).startsWith(workspace));
        assertTrue(Path.of(environment.variables().get("TMPDIR")).startsWith(workspace));
    }

    @Test
    void controlledRunnerHasNoDependencyOnAnyProcessEnvironmentPolicy() {
        // No process is launched in Phase 2B-2 - ProcessEnvironmentPolicy exists as an independently
        // testable future contract, deliberately not yet wired into ControlledRunner's constructor.
        for (var parameterType : ControlledRunner.class.getConstructors()[0].getParameterTypes()) {
            assertNotEquals(ProcessEnvironmentPolicy.class, parameterType);
        }
    }

    // ===================== Source-scan verification (Phase 2B-2 additions included) =====================

    @Test
    void runnerPackageStillContainsNoProcessOrShellInvocationAfterPhase2b2() throws IOException {
        Path sourceDir = Path.of("src/main/java/com/iacagent/iacagent/runner");
        if (!Files.isDirectory(sourceDir)) {
            return;
        }
        List<String> forbiddenLiterals = List.of(
                "ProcessBuilder", "Runtime.getRuntime().exec", "Runtime.exec",
                "/bin/sh", "\"bash\"", "cmd.exe", "powershell",
                "terraform apply", "terraform destroy", "terraform import", "terraform force-unlock");
        try (var files = Files.walk(sourceDir)) {
            for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                String content = Files.readString(file);
                for (String literal : forbiddenLiterals) {
                    assertFalse(content.contains(literal), file + " must not contain \"" + literal + "\"");
                }
            }
        }
    }

    // System.getenv() legitimately appears as prose inside javadoc comments explaining the
    // build-up-from-empty contract (see ProcessEnvironmentPolicy/AllowlistProcessEnvironmentPolicy)
    // - so this check strips comments before scanning, rather than banning the literal text
    // outright, learning directly from the Phase 2B-1 lesson about literal strings in comments/tests
    // producing false positives.
    @Test
    void allowlistProcessEnvironmentPolicyNeverReadsAmbientProcessEnvironmentOutsideComments() throws IOException {
        Path sourceDir = Path.of("src/main/java/com/iacagent/iacagent/runner");
        if (!Files.isDirectory(sourceDir)) {
            return;
        }
        try (var files = Files.walk(sourceDir)) {
            for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                String codeOnly = stripJavaComments(Files.readString(file));
                assertFalse(codeOnly.contains("System.getenv("), file + " must not read the ambient process environment");
            }
        }
    }

    private static String stripJavaComments(String source) {
        String noBlockComments = source.replaceAll("(?s)/\\*.*?\\*/", "");
        return noBlockComments.replaceAll("(?m)//.*$", "");
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
