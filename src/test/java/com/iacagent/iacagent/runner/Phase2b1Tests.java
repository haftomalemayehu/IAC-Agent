package com.iacagent.iacagent.runner;

import com.iacagent.iacagent.approval.ApprovalIssuanceRequest;
import com.iacagent.iacagent.approval.ApprovalPersistenceException;
import com.iacagent.iacagent.approval.ApprovalProvenance;
import com.iacagent.iacagent.approval.ApprovalProvider;
import com.iacagent.iacagent.approval.ApprovalRecordProducer;
import com.iacagent.iacagent.approval.ApprovalTtlPolicy;
import com.iacagent.iacagent.approval.InMemoryApprovalRepository;
import com.iacagent.iacagent.approval.RepositoryBackedApprovalProvider;
import com.iacagent.iacagent.approval.TrustedApprovalContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.Method;
import java.lang.reflect.RecordComponent;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class Phase2b1Tests {

    private static final Instant NOW = Instant.parse("2026-09-10T00:00:00Z");
    private static final String REPOSITORY = "owner/repository";
    private static final String COMMIT_SHA = "c".repeat(40);
    private static final String ENVIRONMENT = "nonprod";
    private static final String TERRAFORM_VERSION = "1.6.6";
    private static final String PROVIDER_LOCK_HASH = "sha256:lock-abc";
    private static final byte[] PLAN_BYTES = "fake-plan-bytes".getBytes(StandardCharsets.UTF_8);

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

    private static String sha256Hex(byte[] content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(content));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static final String PLAN_SHA256 = sha256Hex(PLAN_BYTES);

    private RunnerIdentity trustedIdentity() {
        return new RunnerIdentity("runner-1", "static-test-runner", Set.of(ENVIRONMENT), true);
    }

    private StoredArtifact validArtifact(String artifactId) {
        return new StoredArtifact(artifactId, PLAN_BYTES, PLAN_BYTES.length, PLAN_SHA256, new ArtifactProvenance("test-fixture"));
    }

    private String issueValidApproval(InMemoryApprovalRepository repo, String planSha) {
        ApprovalRecordProducer producer = new ApprovalRecordProducer(repo, new MutableClock(NOW), ApprovalTtlPolicy.fixed(Duration.ofHours(4)));
        ApprovalIssuanceRequest request = new ApprovalIssuanceRequest(REPOSITORY, COMMIT_SHA, ENVIRONMENT, planSha,
                new ApprovalProvenance("pr-ref", "ci-ref"));
        return producer.issue(request, new TrustedApprovalContext("platform-admin"));
    }

    /** Test-only convenience for constructing RunnerRequest variants - not part of production API. */
    private static final class TestRequestBuilder {
        private final String runnerRequestId;
        private String repository;
        private String commitSha;
        private String environment;
        private final String planArtifactId;
        private String planSha256;
        private String terraformVersion;
        private String providerLockHash;
        private final String approvalId;
        private RunnerOperation requestedOperation;

        TestRequestBuilder(String runnerRequestId, String repository, String commitSha, String environment,
                            String planArtifactId, String planSha256, String terraformVersion, String providerLockHash,
                            String approvalId, RunnerOperation requestedOperation) {
            this.runnerRequestId = runnerRequestId;
            this.repository = repository;
            this.commitSha = commitSha;
            this.environment = environment;
            this.planArtifactId = planArtifactId;
            this.planSha256 = planSha256;
            this.terraformVersion = terraformVersion;
            this.providerLockHash = providerLockHash;
            this.approvalId = approvalId;
            this.requestedOperation = requestedOperation;
        }

        TestRequestBuilder environment(String value) {
            this.environment = value;
            return this;
        }

        TestRequestBuilder terraformVersion(String value) {
            this.terraformVersion = value;
            return this;
        }

        TestRequestBuilder providerLockHash(String value) {
            this.providerLockHash = value;
            return this;
        }

        TestRequestBuilder operation(RunnerOperation value) {
            this.requestedOperation = value;
            return this;
        }

        RunnerRequest build() {
            return new RunnerRequest(runnerRequestId, repository, commitSha, environment, planArtifactId, planSha256,
                    terraformVersion, providerLockHash, approvalId, requestedOperation);
        }
    }

    private TestRequestBuilder baseRequestBuilder(String requestId, String artifactId, String approvalId) {
        return new TestRequestBuilder(requestId, REPOSITORY, COMMIT_SHA, ENVIRONMENT, artifactId, PLAN_SHA256,
                TERRAFORM_VERSION, PROVIDER_LOCK_HASH, approvalId, RunnerOperation.PREPARE_EXECUTION);
    }

    private static final Set<String> ALLOWED_RUNNER_CLASSES = Set.of("static-test-runner");

    private ControlledRunner newRunner(Path root, RunnerIdentity identity, ApprovalProvider approvalProvider, InMemoryRunnerArtifactStore artifactStore) {
        return new ControlledRunner(
                new StaticRunnerIdentityProvider(identity),
                ALLOWED_RUNNER_CLASSES,
                approvalProvider,
                artifactStore,
                new StaticRunnerToolchainContext(TERRAFORM_VERSION, PROVIDER_LOCK_HASH),
                new RunnerWorkspaceManager(root),
                new InMemoryRunnerLedgerRepository(),
                new MutableClock(NOW)
        );
    }

    // 1. trusted runner identity succeeds through PREPARE_EXECUTION
    @Test
    void trustedIdentityWithValidEverythingReachesReadyForFutureExecution(@TempDir Path root) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String approvalId = issueValidApproval(repo, PLAN_SHA256);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(validArtifact("artifact-1"));

        ControlledRunner runner = newRunner(root, trustedIdentity(), new RepositoryBackedApprovalProvider(repo), artifactStore);
        RunnerEvidence evidence = runner.execute(baseRequestBuilder("req-1", "artifact-1", approvalId).build());

        assertEquals(RunnerState.READY_FOR_FUTURE_EXECUTION, evidence.finalState());
        assertTrue(evidence.reasonCodes().isEmpty());
        assertEquals(PLAN_SHA256, evidence.observedPlanSha256());
        assertEquals(TERRAFORM_VERSION, evidence.terraformVersionObserved());
        assertEquals(PROVIDER_LOCK_HASH, evidence.providerLockHashObserved());
        assertTrue(evidence.isReadyForFutureExecution());
    }

    // 2. untrusted runner identity blocks
    @Test
    void untrustedRunnerIdentityBlocks(@TempDir Path root) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String approvalId = issueValidApproval(repo, PLAN_SHA256);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(validArtifact("artifact-1"));
        RunnerIdentity untrusted = new RunnerIdentity("runner-1", "static-test-runner", Set.of(ENVIRONMENT), false);

        ControlledRunner runner = newRunner(root, untrusted, new RepositoryBackedApprovalProvider(repo), artifactStore);
        RunnerEvidence evidence = runner.execute(baseRequestBuilder("req-1", "artifact-1", approvalId).build());

        assertEquals(RunnerState.BLOCKED, evidence.finalState());
        assertEquals(List.of(RunnerReasonCode.RUNNER_IDENTITY_UNTRUSTED), evidence.reasonCodes());
    }

    @Test
    void runnerNotScopedToRequestedEnvironmentBlocks(@TempDir Path root) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String approvalId = issueValidApproval(repo, PLAN_SHA256);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(validArtifact("artifact-1"));
        RunnerIdentity wrongScope = new RunnerIdentity("runner-1", "static-test-runner", Set.of("production"), true);

        ControlledRunner runner = newRunner(root, wrongScope, new RepositoryBackedApprovalProvider(repo), artifactStore);
        RunnerEvidence evidence = runner.execute(baseRequestBuilder("req-1", "artifact-1", approvalId).build());

        assertEquals(RunnerState.BLOCKED, evidence.finalState());
        assertEquals(List.of(RunnerReasonCode.RUNNER_ENVIRONMENT_NOT_ALLOWED), evidence.reasonCodes());
    }

    // 3. caller cannot self-assert runner identity - structural proof
    @Test
    void runnerRequestHasNoIdentityShapedField() {
        Set<String> componentNames = Arrays.stream(RunnerRequest.class.getRecordComponents())
                .map(RecordComponent::getName)
                .collect(Collectors.toSet());
        for (String forbidden : List.of("runnerId", "runnerClass", "trusted", "environmentScope", "identity")) {
            assertFalse(componentNames.contains(forbidden), "RunnerRequest must not carry a " + forbidden + " field");
        }
    }

    @Test
    void controlledRunnerConstructorRequiresAnExternallySuppliedIdentityProvider() throws NoSuchMethodException {
        // The only way ControlledRunner ever learns an identity is via the constructor-injected
        // RunnerIdentityProvider - execute(RunnerRequest) takes no identity parameter at all.
        Method executeMethod = ControlledRunner.class.getMethod("execute", RunnerRequest.class);
        assertEquals(1, executeMethod.getParameterCount());
        assertEquals(RunnerRequest.class, executeMethod.getParameterTypes()[0]);
    }

    // 4. valid approval resolves
    @Test
    void validApprovalResolvesAndAllowsProgressPastApproval(@TempDir Path root) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String approvalId = issueValidApproval(repo, PLAN_SHA256);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(validArtifact("artifact-1"));

        ControlledRunner runner = newRunner(root, trustedIdentity(), new RepositoryBackedApprovalProvider(repo), artifactStore);
        RunnerRequest request = baseRequestBuilder("req-1", "artifact-1", approvalId).operation(RunnerOperation.VERIFY_CONTEXT).build();
        RunnerEvidence evidence = runner.execute(request);

        assertEquals(RunnerState.CONTEXT_VERIFIED, evidence.finalState());
    }

    // 5. expired approval blocks
    @Test
    void expiredApprovalBlocks(@TempDir Path root) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        MutableClock approvalClock = new MutableClock(NOW);
        ApprovalRecordProducer producer = new ApprovalRecordProducer(repo, approvalClock, ApprovalTtlPolicy.fixed(Duration.ofMinutes(1)));
        String approvalId = producer.issue(new ApprovalIssuanceRequest(REPOSITORY, COMMIT_SHA, ENVIRONMENT, PLAN_SHA256, ApprovalProvenance.NONE),
                new TrustedApprovalContext("platform-admin"));
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(validArtifact("artifact-1"));

        ControlledRunner runner = new ControlledRunner(
                new StaticRunnerIdentityProvider(trustedIdentity()),
                ALLOWED_RUNNER_CLASSES,
                new RepositoryBackedApprovalProvider(repo),
                artifactStore,
                new StaticRunnerToolchainContext(TERRAFORM_VERSION, PROVIDER_LOCK_HASH),
                new RunnerWorkspaceManager(root),
                new InMemoryRunnerLedgerRepository(),
                new MutableClock(NOW.plus(Duration.ofHours(1))));

        RunnerEvidence evidence = runner.execute(baseRequestBuilder("req-1", "artifact-1", approvalId).build());

        assertEquals(RunnerState.BLOCKED, evidence.finalState());
        assertEquals(List.of(RunnerReasonCode.APPROVAL_EXPIRED), evidence.reasonCodes());
    }

    // 6. revoked approval blocks
    @Test
    void revokedApprovalBlocks(@TempDir Path root) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        ApprovalRecordProducer producer = new ApprovalRecordProducer(repo, new MutableClock(NOW), ApprovalTtlPolicy.fixed(Duration.ofHours(4)));
        String approvalId = producer.issue(new ApprovalIssuanceRequest(REPOSITORY, COMMIT_SHA, ENVIRONMENT, PLAN_SHA256, ApprovalProvenance.NONE),
                new TrustedApprovalContext("platform-admin"));
        producer.revoke(approvalId, new TrustedApprovalContext("security-lead"), "rotated");
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(validArtifact("artifact-1"));

        ControlledRunner runner = newRunner(root, trustedIdentity(), new RepositoryBackedApprovalProvider(repo), artifactStore);
        RunnerEvidence evidence = runner.execute(baseRequestBuilder("req-1", "artifact-1", approvalId).build());

        assertEquals(RunnerState.BLOCKED, evidence.finalState());
        assertEquals(List.of(RunnerReasonCode.APPROVAL_REVOKED), evidence.reasonCodes());
    }

    // 7. superseded approval blocks
    @Test
    void supersededApprovalBlocks(@TempDir Path root) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        ApprovalRecordProducer producer = new ApprovalRecordProducer(repo, new MutableClock(NOW), ApprovalTtlPolicy.fixed(Duration.ofHours(4)));
        String oldApprovalId = producer.issue(new ApprovalIssuanceRequest(REPOSITORY, COMMIT_SHA, ENVIRONMENT, PLAN_SHA256, ApprovalProvenance.NONE),
                new TrustedApprovalContext("platform-admin"));
        producer.issueSuperseding(new ApprovalIssuanceRequest(REPOSITORY, COMMIT_SHA, ENVIRONMENT, "sha256:new-plan", ApprovalProvenance.NONE),
                new TrustedApprovalContext("platform-admin"), oldApprovalId);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(validArtifact("artifact-1"));

        ControlledRunner runner = newRunner(root, trustedIdentity(), new RepositoryBackedApprovalProvider(repo), artifactStore);
        RunnerEvidence evidence = runner.execute(baseRequestBuilder("req-1", "artifact-1", oldApprovalId).build());

        assertEquals(RunnerState.BLOCKED, evidence.finalState());
        assertEquals(List.of(RunnerReasonCode.APPROVAL_SUPERSEDED), evidence.reasonCodes());
    }

    // 8. approval store unavailable fails closed
    @Test
    void approvalStoreUnavailableFailsClosed(@TempDir Path root) {
        ApprovalProvider throwingProvider = id -> {
            throw new ApprovalPersistenceException("durable approval store unavailable", new RuntimeException("connection refused"));
        };
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(validArtifact("artifact-1"));

        ControlledRunner runner = newRunner(root, trustedIdentity(), throwingProvider, artifactStore);
        RunnerEvidence evidence = runner.execute(baseRequestBuilder("req-1", "artifact-1", "approval-x").build());

        assertEquals(RunnerState.BLOCKED, evidence.finalState());
        assertEquals(List.of(RunnerReasonCode.DURABLE_APPROVAL_STORE_UNAVAILABLE), evidence.reasonCodes());
    }

    // 9. artifact not found blocks
    @Test
    void artifactNotFoundBlocks(@TempDir Path root) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String approvalId = issueValidApproval(repo, PLAN_SHA256);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore(); // nothing staged

        ControlledRunner runner = newRunner(root, trustedIdentity(), new RepositoryBackedApprovalProvider(repo), artifactStore);
        RunnerEvidence evidence = runner.execute(baseRequestBuilder("req-1", "does-not-exist", approvalId).build());

        assertEquals(RunnerState.BLOCKED, evidence.finalState());
        assertEquals(List.of(RunnerReasonCode.ARTIFACT_NOT_FOUND), evidence.reasonCodes());
    }

    // 10. artifact hash mismatch blocks
    @Test
    void artifactHashMismatchBlocks(@TempDir Path root) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String approvalId = issueValidApproval(repo, PLAN_SHA256);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        // store content that does NOT match the recorded hash it claims
        artifactStore.stage(new StoredArtifact("artifact-1", "tampered-bytes".getBytes(StandardCharsets.UTF_8), 1, PLAN_SHA256, ArtifactProvenance.NONE));

        ControlledRunner runner = newRunner(root, trustedIdentity(), new RepositoryBackedApprovalProvider(repo), artifactStore);
        RunnerEvidence evidence = runner.execute(baseRequestBuilder("req-1", "artifact-1", approvalId).build());

        assertEquals(RunnerState.BLOCKED, evidence.finalState());
        assertEquals(List.of(RunnerReasonCode.ARTIFACT_HASH_MISMATCH), evidence.reasonCodes());
    }

    @Test
    void artifactMatchingStoreButNotRequestedPlanHashBlocks(@TempDir Path root) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        // approval covers a DIFFERENT plan hash than the artifact actually staged
        String approvalId = issueValidApproval(repo, "sha256:different-approved-hash");
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(validArtifact("artifact-1")); // internally consistent, but not what was approved

        ControlledRunner runner = newRunner(root, trustedIdentity(), new RepositoryBackedApprovalProvider(repo), artifactStore);
        RunnerEvidence evidence = runner.execute(baseRequestBuilder("req-1", "artifact-1", approvalId).build());

        // caught earlier, at approval validation (plan hash mismatch against the approval) -
        // before the runner even attempts to resolve the artifact
        assertEquals(RunnerState.BLOCKED, evidence.finalState());
        assertEquals(List.of(RunnerReasonCode.PLAN_HASH_MISMATCH), evidence.reasonCodes());
    }

    // 11. recomputed hash match succeeds (covered by test 1's READY_FOR_FUTURE_EXECUTION, plus this
    // narrower VERIFY_ARTIFACT-only check)
    @Test
    void recomputedHashMatchSucceedsForVerifyArtifactOperation(@TempDir Path root) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String approvalId = issueValidApproval(repo, PLAN_SHA256);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(validArtifact("artifact-1"));

        ControlledRunner runner = newRunner(root, trustedIdentity(), new RepositoryBackedApprovalProvider(repo), artifactStore);
        RunnerRequest request = baseRequestBuilder("req-1", "artifact-1", approvalId).operation(RunnerOperation.VERIFY_ARTIFACT).build();
        RunnerEvidence evidence = runner.execute(request);

        assertEquals(RunnerState.ARTIFACT_VERIFIED, evidence.finalState());
        assertEquals(PLAN_SHA256, evidence.observedPlanSha256());
        assertTrue(evidence.reasonCodes().isEmpty());
    }

    // 12. Terraform-version mismatch blocks
    @Test
    void terraformVersionMismatchBlocks(@TempDir Path root) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String approvalId = issueValidApproval(repo, PLAN_SHA256);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(validArtifact("artifact-1"));

        ControlledRunner runner = newRunner(root, trustedIdentity(), new RepositoryBackedApprovalProvider(repo), artifactStore);
        RunnerRequest request = baseRequestBuilder("req-1", "artifact-1", approvalId).terraformVersion("9.9.9").build();
        RunnerEvidence evidence = runner.execute(request);

        assertEquals(RunnerState.BLOCKED, evidence.finalState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_VERSION_MISMATCH), evidence.reasonCodes());
    }

    // 13. provider-lock-hash mismatch blocks
    @Test
    void providerLockHashMismatchBlocks(@TempDir Path root) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String approvalId = issueValidApproval(repo, PLAN_SHA256);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(validArtifact("artifact-1"));

        ControlledRunner runner = newRunner(root, trustedIdentity(), new RepositoryBackedApprovalProvider(repo), artifactStore);
        RunnerRequest request = baseRequestBuilder("req-1", "artifact-1", approvalId).providerLockHash("sha256:wrong-lock").build();
        RunnerEvidence evidence = runner.execute(request);

        assertEquals(RunnerState.BLOCKED, evidence.finalState());
        assertEquals(List.of(RunnerReasonCode.PROVIDER_LOCK_HASH_MISMATCH), evidence.reasonCodes());
    }

    // 14. unsupported/mutation operation cannot be represented
    @Test
    void runnerOperationHasNoMutationValue() {
        Set<String> operationNames = Arrays.stream(RunnerOperation.values()).map(Enum::name).collect(Collectors.toSet());
        // Phase 2B-3 added TERRAFORM_VERSION/TERRAFORM_FMT_CHECK/TERRAFORM_SHOW_PLAN_JSON - all
        // non-mutating (they launch a real process for the first time, but none of the three can
        // change infrastructure, state, or configuration) - see docs/phase-2b3-controlled-terraform-process.md.
        // Phase 2B-4 added TERRAFORM_INIT/TERRAFORM_VALIDATE/TERRAFORM_PROVIDERS_SCHEMA under a
        // policy-governed provider/module/backend trust boundary - still no PLAN/APPLY - see
        // docs/phase-2b4-controlled-init-validation.md.
        assertEquals(Set.of("VERIFY_ARTIFACT", "VERIFY_CONTEXT", "PREPARE_EXECUTION",
                "TERRAFORM_VERSION", "TERRAFORM_FMT_CHECK", "TERRAFORM_SHOW_PLAN_JSON",
                "TERRAFORM_INIT", "TERRAFORM_VALIDATE", "TERRAFORM_PROVIDERS_SCHEMA"), operationNames);
        for (String forbidden : List.of("APPLY", "DESTROY", "IMPORT", "STATE_RM", "STATE_MV", "FORCE_UNLOCK", "SHELL", "EXECUTE",
                "PLAN", "REFRESH", "TAINT", "UNTAINT", "WORKSPACE")) {
            assertFalse(operationNames.contains(forbidden), forbidden + " must not be a representable RunnerOperation");
        }
    }

    @Test
    void runnerStateHasNoMutationState() {
        Set<String> stateNames = Arrays.stream(RunnerState.values()).map(Enum::name).collect(Collectors.toSet());
        for (String forbidden : List.of("APPLYING", "APPLIED", "MUTATED", "MUTATING")) {
            assertFalse(stateNames.contains(forbidden));
        }
    }

    // 15/16. no shell/general-command API; no ProcessBuilder anywhere in the package
    @Test
    void controlledRunnerExposesNoGeneralCommandInterface() {
        Set<String> methodNames = Arrays.stream(ControlledRunner.class.getDeclaredMethods())
                .filter(m -> java.lang.reflect.Modifier.isPublic(m.getModifiers()))
                .map(Method::getName)
                .collect(Collectors.toSet());
        // execute() is the sole mutation-adjacent (well, preparation-adjacent) operation;
        // historicalEvidence() is a read-only audit accessor, not a command surface.
        assertEquals(Set.of("execute", "historicalEvidence"), methodNames, "ControlledRunner must expose no operation beyond execute() and the read-only historicalEvidence() accessor");

        Method execute = Arrays.stream(ControlledRunner.class.getDeclaredMethods())
                .filter(m -> m.getName().equals("execute")).findFirst().orElseThrow();
        assertFalse(List.of(execute.getParameterTypes()).contains(String.class),
                "execute() must not accept a raw String (command/shell) parameter");
    }

    // As of Phase 2B-3, ProcessBuilder is intentionally permitted in exactly one place -
    // ControlledTerraformProcess, the dedicated, narrow process boundary. This test now enforces
    // that narrower invariant rather than an absolute absence - see Phase2b3Tests for the fuller
    // Phase 2B-3 source-scan (Runtime.exec, shell invocation, and the full terraform-apply-family
    // literal list) that still applies package-wide with no exception.
    @Test
    void runnerPackageContainsNoProcessInvocationOutsideTheControlledTerraformProcessClass() throws Exception {
        Path sourceDir = Path.of("src/main/java/com/iacagent/iacagent/runner");
        if (!Files.isDirectory(sourceDir)) {
            return; // not available in this execution context (e.g. packaged jar) - best-effort check
        }
        try (var files = Files.walk(sourceDir)) {
            for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                String content = Files.readString(file);
                boolean isTheOneAllowedProcessBoundaryClass = file.getFileName().toString().equals("ControlledTerraformProcess.java");
                if (!isTheOneAllowedProcessBoundaryClass) {
                    assertFalse(content.contains("ProcessBuilder"), file + " must not reference ProcessBuilder");
                }
                assertFalse(content.contains("Runtime.getRuntime().exec"), file + " must not invoke Runtime.exec");
            }
        }
    }

    // 17. two concurrent requests use isolated workspaces
    @Test
    void concurrentRequestsUseIsolatedWorkspaces(@TempDir Path root) throws Exception {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        byte[] planA = "plan-A-bytes".getBytes(StandardCharsets.UTF_8);
        byte[] planB = "plan-B-bytes-longer".getBytes(StandardCharsets.UTF_8);
        String shaA = sha256Hex(planA);
        String shaB = sha256Hex(planB);
        ApprovalRecordProducer producer = new ApprovalRecordProducer(repo, new MutableClock(NOW), ApprovalTtlPolicy.fixed(Duration.ofHours(4)));
        String approvalA = producer.issue(new ApprovalIssuanceRequest(REPOSITORY, COMMIT_SHA, ENVIRONMENT, shaA, ApprovalProvenance.NONE), new TrustedApprovalContext("platform-admin"));
        String approvalB = producer.issue(new ApprovalIssuanceRequest(REPOSITORY, COMMIT_SHA, ENVIRONMENT, shaB, ApprovalProvenance.NONE), new TrustedApprovalContext("platform-admin"));

        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(new StoredArtifact("artifact-A", planA, planA.length, shaA, ArtifactProvenance.NONE));
        artifactStore.stage(new StoredArtifact("artifact-B", planB, planB.length, shaB, ArtifactProvenance.NONE));

        ControlledRunner runner = newRunner(root, trustedIdentity(), new RepositoryBackedApprovalProvider(repo), artifactStore);

        RunnerRequest requestA = new TestRequestBuilder("req-A", REPOSITORY, COMMIT_SHA, ENVIRONMENT, "artifact-A", shaA,
                TERRAFORM_VERSION, PROVIDER_LOCK_HASH, approvalA, RunnerOperation.PREPARE_EXECUTION).build();
        RunnerRequest requestB = new TestRequestBuilder("req-B", REPOSITORY, COMMIT_SHA, ENVIRONMENT, "artifact-B", shaB,
                TERRAFORM_VERSION, PROVIDER_LOCK_HASH, approvalB, RunnerOperation.PREPARE_EXECUTION).build();

        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch go = new CountDownLatch(1);
        AtomicReference<RunnerEvidence> resultA = new AtomicReference<>();
        AtomicReference<RunnerEvidence> resultB = new AtomicReference<>();
        ExecutorService pool = Executors.newFixedThreadPool(2);
        pool.submit(() -> {
            ready.countDown();
            awaitUninterruptibly(go);
            resultA.set(runner.execute(requestA));
        });
        pool.submit(() -> {
            ready.countDown();
            awaitUninterruptibly(go);
            resultB.set(runner.execute(requestB));
        });
        ready.await();
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

        assertEquals(RunnerState.READY_FOR_FUTURE_EXECUTION, resultA.get().finalState());
        assertEquals(RunnerState.READY_FOR_FUTURE_EXECUTION, resultB.get().finalState());
        // Each request's evidence carries only its own observed hash - never the other request's -
        // which is exactly what would fail to hold if the two requests shared a workspace or one
        // request's staged bytes leaked into the other's verification.
        assertEquals(shaA, resultA.get().observedPlanSha256());
        assertEquals(shaB, resultB.get().observedPlanSha256());

        // Since Phase 2B-2, ControlledRunner cleans up each request's workspace immediately after
        // its terminal evidence is durably recorded (see RunnerWorkspaceManager#cleanup), so no
        // filesystem trace of either workspace is expected to survive execute() returning; the
        // per-workspace isolation guarantee itself (separate dirs, no cross-contamination of
        // staged bytes) is covered directly against RunnerWorkspaceManager, bypassing cleanup, in
        // workspaceManagerKeepsConcurrentRequestsIsolatedBeforeCleanup below.
        try (var listing = Files.list(root)) {
            assertEquals(0, listing.filter(Files::isDirectory).count(),
                    "both requests' workspaces must be cleaned up after their evidence is recorded, with no cross-request leftovers");
        }
    }

    // 20. isolation guarantee at the layer that actually owns it: two concurrent requests get
    // distinct, content-addressed directories, and neither can see the other's staged artifact -
    // verified directly against RunnerWorkspaceManager, before ControlledRunner's post-recording
    // cleanup would otherwise remove the evidence from disk.
    @Test
    void workspaceManagerKeepsConcurrentRequestsIsolatedBeforeCleanup(@TempDir Path root) throws Exception {
        RunnerWorkspaceManager manager = new RunnerWorkspaceManager(root);
        byte[] planA = "plan-A-bytes".getBytes(StandardCharsets.UTF_8);
        byte[] planB = "plan-B-bytes-longer".getBytes(StandardCharsets.UTF_8);
        String shaA = sha256Hex(planA);
        String shaB = sha256Hex(planB);

        Path workspaceA = manager.createWorkspace("req-A");
        Path workspaceB = manager.createWorkspace("req-B");
        assertNotEquals(workspaceA, workspaceB, "distinct requests must never share a workspace directory");

        Path stagedA = manager.stageArtifact(workspaceA, shaA, planA);
        Path stagedB = manager.stageArtifact(workspaceB, shaB, planB);

        assertFalse(Files.exists(workspaceA.resolve(stagedB.getFileName())), "A's workspace must not contain B's artifact");
        assertFalse(Files.exists(workspaceB.resolve(stagedA.getFileName())), "B's workspace must not contain A's artifact");
        assertArrayEquals(planA, Files.readAllBytes(stagedA));
        assertArrayEquals(planB, Files.readAllBytes(stagedB));

        // cleanup of one request's workspace must never touch the other's
        assertTrue(manager.cleanup(workspaceA));
        assertFalse(Files.exists(workspaceA), "A's workspace must be gone after its own cleanup");
        assertTrue(Files.exists(stagedB), "B's workspace and artifact must survive A's cleanup");
    }

    private static void awaitUninterruptibly(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
    }

    // 18. duplicate request IDs follow the chosen deterministic rule: a resubmission is NEVER
    // returned as if it were a fresh authorization decision, even when identical - only the
    // first execute() call for a given id can ever return READY_FOR_FUTURE_EXECUTION.
    @Test
    void duplicateRequestIdWithIdenticalContentBlocksRatherThanReplayingReadyResult(@TempDir Path root) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String approvalId = issueValidApproval(repo, PLAN_SHA256);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(validArtifact("artifact-1"));
        ControlledRunner runner = newRunner(root, trustedIdentity(), new RepositoryBackedApprovalProvider(repo), artifactStore);

        RunnerRequest request = baseRequestBuilder("req-dup", "artifact-1", approvalId).build();
        RunnerEvidence first = runner.execute(request);
        RunnerEvidence second = runner.execute(request);

        assertEquals(RunnerState.READY_FOR_FUTURE_EXECUTION, first.finalState());
        assertEquals(RunnerState.BLOCKED, second.finalState(), "a resubmission must never be returned as a fresh READY authorization");
        assertEquals(List.of(RunnerReasonCode.DUPLICATE_RUNNER_REQUEST), second.reasonCodes());
    }

    @Test
    void duplicateRequestIdWithDifferentContentIsRejectedWithFingerprintMismatch(@TempDir Path root) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String approvalId = issueValidApproval(repo, PLAN_SHA256);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(validArtifact("artifact-1"));
        ControlledRunner runner = newRunner(root, trustedIdentity(), new RepositoryBackedApprovalProvider(repo), artifactStore);

        RunnerRequest first = baseRequestBuilder("req-dup2", "artifact-1", approvalId).build();
        RunnerEvidence firstResult = runner.execute(first);
        RunnerRequest conflicting = baseRequestBuilder("req-dup2", "artifact-1", approvalId).environment("production").build();
        RunnerEvidence conflictResult = runner.execute(conflicting);

        assertEquals(RunnerState.READY_FOR_FUTURE_EXECUTION, firstResult.finalState());
        assertEquals(RunnerState.BLOCKED, conflictResult.finalState());
        assertEquals(List.of(RunnerReasonCode.RUNNER_REQUEST_FINGERPRINT_MISMATCH), conflictResult.reasonCodes());
    }

    // Original evidence remains unchanged/retrievable for audit, separate from execute()'s result.
    @Test
    void originalEvidenceRemainsRetrievableAsHistoricalEvidenceAfterDuplicateAttempts(@TempDir Path root) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String approvalId = issueValidApproval(repo, PLAN_SHA256);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(validArtifact("artifact-1"));
        ControlledRunner runner = newRunner(root, trustedIdentity(), new RepositoryBackedApprovalProvider(repo), artifactStore);

        RunnerRequest request = baseRequestBuilder("req-dup3", "artifact-1", approvalId).build();
        RunnerEvidence first = runner.execute(request);
        runner.execute(request); // duplicate attempt, blocked
        runner.execute(baseRequestBuilder("req-dup3", "artifact-1", approvalId).environment("production").build()); // conflicting attempt, blocked

        RunnerEvidence historical = runner.historicalEvidence("req-dup3").orElseThrow();
        assertSame(first, historical, "the original evidence must remain exactly as it was, unaffected by later duplicate/conflicting attempts");
        assertEquals(RunnerState.READY_FOR_FUTURE_EXECUTION, historical.finalState());
    }

    // A duplicate request must not receive prior READY evidence once approval has since been
    // revoked - the whole point of this amendment.
    @Test
    void duplicateRequestAfterApprovalRevocationDoesNotReceivePriorReadyEvidence(@TempDir Path root) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        ApprovalRecordProducer producer = new ApprovalRecordProducer(repo, new MutableClock(NOW), ApprovalTtlPolicy.fixed(Duration.ofHours(4)));
        String approvalId = producer.issue(new ApprovalIssuanceRequest(REPOSITORY, COMMIT_SHA, ENVIRONMENT, PLAN_SHA256, ApprovalProvenance.NONE),
                new TrustedApprovalContext("platform-admin"));
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(validArtifact("artifact-1"));
        ControlledRunner runner = newRunner(root, trustedIdentity(), new RepositoryBackedApprovalProvider(repo), artifactStore);

        RunnerRequest request = baseRequestBuilder("req-revoked-replay", "artifact-1", approvalId).build();
        RunnerEvidence first = runner.execute(request);
        assertEquals(RunnerState.READY_FOR_FUTURE_EXECUTION, first.finalState());

        producer.revoke(approvalId, new TrustedApprovalContext("security-lead"), "compromise suspected");

        RunnerEvidence replay = runner.execute(request);
        assertEquals(RunnerState.BLOCKED, replay.finalState());
        assertEquals(List.of(RunnerReasonCode.DUPLICATE_RUNNER_REQUEST), replay.reasonCodes(),
                "the resubmission is blocked as a duplicate, not silently re-validated and not returned as READY");
        assertNotEquals(RunnerState.READY_FOR_FUTURE_EXECUTION, replay.finalState(),
                "an old READY result must never be handed out again after the approval it depended on was revoked");
    }

    // Same, for expiry rather than explicit revocation.
    @Test
    void duplicateRequestAfterApprovalExpirationDoesNotReceivePriorReadyEvidence(@TempDir Path root) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        MutableClock approvalClock = new MutableClock(NOW);
        ApprovalRecordProducer producer = new ApprovalRecordProducer(repo, approvalClock, ApprovalTtlPolicy.fixed(Duration.ofMinutes(1)));
        String approvalId = producer.issue(new ApprovalIssuanceRequest(REPOSITORY, COMMIT_SHA, ENVIRONMENT, PLAN_SHA256, ApprovalProvenance.NONE),
                new TrustedApprovalContext("platform-admin"));
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(validArtifact("artifact-1"));

        MutableClock runnerClock = new MutableClock(NOW);
        ControlledRunner runner = new ControlledRunner(
                new StaticRunnerIdentityProvider(trustedIdentity()),
                ALLOWED_RUNNER_CLASSES,
                new RepositoryBackedApprovalProvider(repo),
                artifactStore,
                new StaticRunnerToolchainContext(TERRAFORM_VERSION, PROVIDER_LOCK_HASH),
                new RunnerWorkspaceManager(root),
                new InMemoryRunnerLedgerRepository(),
                runnerClock);

        RunnerRequest request = baseRequestBuilder("req-expired-replay", "artifact-1", approvalId).build();
        RunnerEvidence first = runner.execute(request);
        assertEquals(RunnerState.READY_FOR_FUTURE_EXECUTION, first.finalState());

        runnerClock.set(NOW.plus(Duration.ofHours(1))); // well past the 1-minute TTL

        RunnerEvidence replay = runner.execute(request);
        assertEquals(RunnerState.BLOCKED, replay.finalState());
        assertEquals(List.of(RunnerReasonCode.DUPLICATE_RUNNER_REQUEST), replay.reasonCodes());
        assertNotEquals(RunnerState.READY_FOR_FUTURE_EXECUTION, replay.finalState(),
                "an old READY result must never be handed out again after the approval it depended on expired");
    }

    // Malicious request IDs cannot escape or influence the workspace root.
    @Test
    void maliciousRunnerRequestIdsCannotEscapeWorkspaceRoot(@TempDir Path root) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(validArtifact("artifact-1"));
        ControlledRunner runner = newRunner(root, trustedIdentity(), new RepositoryBackedApprovalProvider(repo), artifactStore);

        List<String> hostileIds = List.of("../../evil", "/etc/passwd", "..", ".", "a/b/c", "..\\..\\evil", "~/evil");
        for (String hostileId : hostileIds) {
            String approvalId = issueValidApproval(repo, PLAN_SHA256);
            RunnerRequest request = baseRequestBuilder(hostileId, "artifact-1", approvalId).build();
            RunnerEvidence evidence = runner.execute(request);

            assertEquals(RunnerState.READY_FOR_FUTURE_EXECUTION, evidence.finalState(), "hostile id: " + hostileId);
        }

        // No file or directory was ever created outside the configured root, regardless of id content.
        try (var listing = Files.walk(root)) {
            listing.forEach(p -> assertTrue(p.normalize().startsWith(root.normalize()), "path escaped root: " + p));
        } catch (java.io.IOException e) {
            fail(e);
        }
        // and nothing was created directly at the repo/filesystem root as a side effect either
        assertFalse(Files.exists(Path.of("/etc/passwd.tfplan")));
    }

    @Test
    void runnerWorkspaceManagerRejectsBlankRequestId(@TempDir Path root) {
        RunnerWorkspaceManager manager = new RunnerWorkspaceManager(root);
        assertThrows(IllegalArgumentException.class, () -> manager.createWorkspace(""));
        assertThrows(IllegalArgumentException.class, () -> manager.createWorkspace(null));
    }

    // 19. evidence contains expected/observed values and final reason codes
    @Test
    void evidenceCapturesExpectedAndObservedValuesOnMismatch(@TempDir Path root) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String approvalId = issueValidApproval(repo, PLAN_SHA256);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(validArtifact("artifact-1"));
        ControlledRunner runner = newRunner(root, trustedIdentity(), new RepositoryBackedApprovalProvider(repo), artifactStore);

        RunnerRequest request = baseRequestBuilder("req-1", "artifact-1", approvalId).terraformVersion("9.9.9").build();
        RunnerEvidence evidence = runner.execute(request);

        assertEquals("9.9.9", evidence.terraformVersionExpected());
        assertEquals(TERRAFORM_VERSION, evidence.terraformVersionObserved());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_VERSION_MISMATCH), evidence.reasonCodes());
        assertNotNull(evidence.startedAt());
        assertNotNull(evidence.completedAt());
    }

    // 20. evidence does not contain arbitrary environment or secret values (structural)
    @Test
    void runnerEvidenceHasNoEnvironmentOrSecretField() {
        Set<String> componentNames = Arrays.stream(RunnerEvidence.class.getRecordComponents())
                .map(RecordComponent::getName)
                .collect(Collectors.toSet());
        for (String forbidden : List.of("environmentVariables", "secrets", "credentials", "rawEnvironment", "envDump")) {
            assertFalse(componentNames.contains(forbidden));
        }
    }
}
