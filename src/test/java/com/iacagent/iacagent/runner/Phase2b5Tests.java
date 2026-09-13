package com.iacagent.iacagent.runner;

import com.iacagent.iacagent.approval.ApprovalIssuanceRequest;
import com.iacagent.iacagent.approval.ApprovalProvenance;
import com.iacagent.iacagent.approval.ApprovalRecordProducer;
import com.iacagent.iacagent.approval.ApprovalTtlPolicy;
import com.iacagent.iacagent.approval.InMemoryApprovalRepository;
import com.iacagent.iacagent.approval.RepositoryBackedApprovalProvider;
import com.iacagent.iacagent.approval.TrustedApprovalContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.UncheckedIOException;
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
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 2B-5 tests: the controlled Terraform {@code plan} + state-read boundary. Covers trusted
 * backend/state resolution (never caller/repository-controlled), the runner-owned backend
 * declaration file (repository {@code backend} blocks rejected outright), the real (never
 * {@code -backend=false}) init-for-plan step, {@code -detailed-exitcode} semantics (0/2 both
 * success, never generic failure), saved-plan artifact path/hash safety, the durable plan artifact
 * store, {@code planInputSha256} binding every semantic input, and credential redaction.
 *
 * <p>Fake POSIX shell-script executables ({@link FakeExecutables#terraformPlanStub}) stand in for
 * Terraform - no test here depends on real state, real credentials, or network access.
 */
class Phase2b5Tests {

    private static final Instant NOW = Instant.parse("2026-09-13T00:00:00Z");
    private static final String REPOSITORY = "owner/repository";
    private static final String COMMIT_SHA = "c".repeat(40);
    private static final String ENVIRONMENT = "nonprod";
    private static final String TERRAFORM_VERSION_EXPECTED = "1.6.6";
    private static final String PROVIDER_LOCK_HASH = "sha256:lock-abc";
    private static final Set<String> ALLOWED_RUNNER_CLASSES = Set.of("terraform-test-runner");

    private static final byte[] PROVIDERLESS_CONFIG = "resource \"terraform_data\" \"x\" {}\n".getBytes(StandardCharsets.UTF_8);
    private static final String INIT_OK = "exit 0\n";
    private static final String SHOW_EMPTY = "echo '{}'\nexit 0\n";

    private static final class MutableClock extends Clock {
        private final Instant instant;

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

    private RunnerIdentity trustedIdentity() {
        return new RunnerIdentity("runner-1", "terraform-test-runner", Set.of(ENVIRONMENT), true);
    }

    private String issueValidApproval(InMemoryApprovalRepository repo, String planSha) {
        ApprovalRecordProducer producer = new ApprovalRecordProducer(repo, new MutableClock(NOW), ApprovalTtlPolicy.fixed(Duration.ofHours(4)));
        ApprovalIssuanceRequest request = new ApprovalIssuanceRequest(REPOSITORY, COMMIT_SHA, ENVIRONMENT, planSha, ApprovalProvenance.NONE);
        return producer.issue(request, new TrustedApprovalContext("platform-admin"));
    }

    private RunnerRequest baseRequest(String requestId, String artifactId, String planSha256, String approvalId, RunnerOperation operation) {
        return new RunnerRequest(requestId, REPOSITORY, COMMIT_SHA, ENVIRONMENT, artifactId, planSha256,
                TERRAFORM_VERSION_EXPECTED, PROVIDER_LOCK_HASH, approvalId, operation);
    }

    private RunnerRequest baseRequest(String requestId, String artifactId, String planSha256, String approvalId, RunnerOperation operation, String environment) {
        return new RunnerRequest(requestId, REPOSITORY, COMMIT_SHA, environment, artifactId, planSha256,
                TERRAFORM_VERSION_EXPECTED, PROVIDER_LOCK_HASH, approvalId, operation);
    }

    private static List<TerraformConfigIdentity.NamedConfigFile> singleFile(byte[] content) {
        return List.of(new TerraformConfigIdentity.NamedConfigFile("main.tf", content));
    }

    // ===================== structural =====================

    @Test
    void terraformPlanIsAClosedOperationInBothEnums() {
        assertTrue(Set.of(ControlledTerraformOperation.values()).contains(ControlledTerraformOperation.TERRAFORM_PLAN));
        assertTrue(Set.of(RunnerOperation.values()).contains(RunnerOperation.TERRAFORM_PLAN));
        for (var value : ControlledTerraformOperation.values()) {
            assertNotEquals("TERRAFORM_APPLY", value.name());
            assertNotEquals("TERRAFORM_DESTROY", value.name());
        }
    }

    @Test
    void planCommandArgvContainsDetailedExitcodeAndExcludesDangerousFlags() {
        TerraformCommandFactory factory = new TerraformCommandFactory(new TerraformProcessEnvironmentPolicy(), new TerraformInitProcessEnvironmentPolicy());
        TerraformExecutableDescriptor descriptor = new TerraformExecutableDescriptor(Path.of("/tools/terraform"), "sha", "1.6.6", Path.of("/tools"));
        ControlledTerraformCommand command = factory.planCommand(
                baseRequest("r", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), descriptor, Path.of("/work"), Path.of("/work/plan/tfplan"), Duration.ofSeconds(5), Map.of());

        assertTrue(command.argv().contains("plan"));
        assertTrue(command.argv().contains("-detailed-exitcode"));
        assertTrue(command.argv().contains("-out=/work/plan/tfplan"));
        for (String forbidden : List.of("-destroy", "-refresh-only", "-target", "-replace", "-state", "-state-out",
                "-var", "-var-file", "-parallelism", "-lock=false", "-backend-config")) {
            assertFalse(command.argv().stream().anyMatch(a -> a.equals(forbidden) || a.startsWith(forbidden + "=") || a.startsWith(forbidden + " ")),
                    forbidden + " must never appear in plan argv");
        }
    }

    @Test
    void initForPlanCommandArgvOmitsBackendFalse() {
        TerraformCommandFactory factory = new TerraformCommandFactory(new TerraformProcessEnvironmentPolicy(), new TerraformInitProcessEnvironmentPolicy());
        TerraformExecutableDescriptor descriptor = new TerraformExecutableDescriptor(Path.of("/tools/terraform"), "sha", "1.6.6", Path.of("/tools"));
        ControlledTerraformCommand command = factory.initForPlanCommand(
                baseRequest("r", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), descriptor, Path.of("/work"), Duration.ofSeconds(5), Map.of());

        assertFalse(command.argv().contains("-backend=false"), "init-for-plan must allow the real backend to take effect");
        assertTrue(command.argv().contains("-lockfile=readonly"));
    }

    @Test
    void runnerRequestHasNoBackendOrStateField() {
        // "lock" is deliberately excluded from this list - providerLockHash is a legitimate,
        // already-accepted field from earlier phases, not a backend/state-target selector.
        List<String> forbidden = List.of("backend", "statekey", "stateidentity", "credential");
        for (RecordComponent component : RunnerRequest.class.getRecordComponents()) {
            String lower = component.getName().toLowerCase();
            for (String bad : forbidden) {
                assertFalse(lower.contains(bad), "RunnerRequest must not carry a field that could choose backend/state/credentials: " + component.getName());
            }
        }
    }

    // ===================== trusted backend/state resolution =====================

    @Test
    void sameRepositoryAndEnvironmentProduceAStableStateIdentity(@TempDir Path stateRoot) {
        var resolver = new ReferenceLocalBackendResolver(stateRoot);
        var a = resolver.resolve(REPOSITORY, ENVIRONMENT);
        var b = resolver.resolve(REPOSITORY, ENVIRONMENT);
        assertEquals(a.stateIdentity().sha256Hex(), b.stateIdentity().sha256Hex());
        assertEquals(a.localStatePath(), b.localStatePath());
    }

    @Test
    void differentEnvironmentsResolveDifferentStateIdentities(@TempDir Path stateRoot) {
        var resolver = new ReferenceLocalBackendResolver(stateRoot);
        var nonprod = resolver.resolve(REPOSITORY, "nonprod");
        var prod = resolver.resolve(REPOSITORY, "prod");
        assertNotEquals(nonprod.stateIdentity().sha256Hex(), prod.stateIdentity().sha256Hex());
        assertNotEquals(nonprod.localStatePath(), prod.localStatePath());
    }

    @Test
    void differentRepositoriesResolveDifferentStateIdentities(@TempDir Path stateRoot) {
        var resolver = new ReferenceLocalBackendResolver(stateRoot);
        var a = resolver.resolve("owner/a", ENVIRONMENT);
        var b = resolver.resolve("owner/b", ENVIRONMENT);
        assertNotEquals(a.stateIdentity().sha256Hex(), b.stateIdentity().sha256Hex());
    }

    @Test
    void repositoryDeclaredBackendBlockBlocksBeforeAnyProcessLaunches(@TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", SHOW_EMPTY);
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        String maliciousConfig = "terraform {\n  backend \"s3\" {\n    bucket = \"attacker-controlled\"\n  }\n}\n";
        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-backend-block", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace,
                singleFile(maliciousConfig.getBytes(StandardCharsets.UTF_8)));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_BACKEND_BLOCK_NOT_ALLOWED), evidence.reasonCodes());
        assertFalse(Files.exists(marker), "init must never launch once a repository-declared backend block is detected");
    }

    @Test
    void moduleBlockBlocksPlanUnconditionally(@TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", SHOW_EMPTY);
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-module-block", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace,
                singleFile("module \"foo\" {\n  source = \"registry.terraform.io/some/module\"\n}\n".getBytes(StandardCharsets.UTF_8)));

        assertEquals(List.of(RunnerReasonCode.TERRAFORM_MODULE_DEPENDENCY_GRAPH_UNRESOLVED), evidence.reasonCodes());
        assertFalse(Files.exists(marker));
    }

    @Test
    void implicitProviderBlocksPlanBeforeInitEverRuns(@TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", SHOW_EMPTY);
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-implicit-block", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace,
                singleFile("resource \"tls_private_key\" \"key\" {\n  algorithm = \"RSA\"\n}\n".getBytes(StandardCharsets.UTF_8)));

        assertEquals(List.of(RunnerReasonCode.TERRAFORM_PROVIDER_REQUIREMENT_IMPLICIT), evidence.reasonCodes());
        assertFalse(Files.exists(marker));
    }

    // ===================== terraform_remote_state state-boundary escape (security amendment) =====================

    @Test
    void nativeRemoteStateDataSourceWithLocalBackendBlocksBeforeAnyProcessLaunches(
            @TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", SHOW_EMPTY);
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        String maliciousConfig = "data \"terraform_remote_state\" \"other\" {\n"
                + "  backend = \"local\"\n"
                + "  config = {\n"
                + "    path = \"/tmp/attacker-controlled.tfstate\"\n"
                + "  }\n"
                + "}\n";
        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-remote-state-local", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace,
                singleFile(maliciousConfig.getBytes(StandardCharsets.UTF_8)));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_REMOTE_STATE_DATA_SOURCE_NOT_ALLOWED), evidence.reasonCodes());
        assertFalse(Files.exists(marker), "init must never launch once a terraform_remote_state data source is detected");
    }

    @Test
    void nativeRemoteStateDataSourceWithS3BackendBlocksRegardlessOfBackendType(
            @TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", SHOW_EMPTY);
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        String maliciousConfig = "data \"terraform_remote_state\" \"other\" {\n"
                + "  backend = \"s3\"\n"
                + "  config = {\n"
                + "    bucket = \"attacker-controlled\"\n"
                + "    key    = \"attacker/state\"\n"
                + "    region = \"us-east-1\"\n"
                + "  }\n"
                + "}\n";
        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-remote-state-s3", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace,
                singleFile(maliciousConfig.getBytes(StandardCharsets.UTF_8)));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_REMOTE_STATE_DATA_SOURCE_NOT_ALLOWED), evidence.reasonCodes());
        assertFalse(Files.exists(marker), "init must never launch regardless of the remote-state data source's declared backend type");
    }

    @Test
    void jsonSyntaxRemoteStateDataSourceBlocksBeforeAnyProcessLaunches(
            @TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", SHOW_EMPTY);
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        String maliciousConfig = "{\n"
                + "  \"data\": {\n"
                + "    \"terraform_remote_state\": {\n"
                + "      \"other\": {\n"
                + "        \"backend\": \"s3\",\n"
                + "        \"config\": {\n"
                + "          \"bucket\": \"attacker-controlled\",\n"
                + "          \"key\": \"attacker/state\",\n"
                + "          \"region\": \"us-east-1\"\n"
                + "        }\n"
                + "      }\n"
                + "    }\n"
                + "  }\n"
                + "}\n";
        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-remote-state-json", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace,
                List.of(new TerraformConfigIdentity.NamedConfigFile("main.tf.json", maliciousConfig.getBytes(StandardCharsets.UTF_8))));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_REMOTE_STATE_DATA_SOURCE_NOT_ALLOWED), evidence.reasonCodes());
        assertFalse(Files.exists(marker), "init must never launch for a JSON-syntax terraform_remote_state data source either");
    }

    @Test
    void ordinaryDataSourceIsNotFalselyBlockedByRemoteStateCheck(
            @TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", SHOW_EMPTY);
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        // "terraform_data" is the built-in provider's ordinary managed resource, not the
        // remote-state escape - it must still pass through normal (already-exempt) provider rules.
        String ordinaryConfig = "data \"terraform_data\" \"x\" {}\n";
        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-ordinary-data", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace,
                singleFile(ordinaryConfig.getBytes(StandardCharsets.UTF_8)));

        assertNotEquals(List.of(RunnerReasonCode.TERRAFORM_REMOTE_STATE_DATA_SOURCE_NOT_ALLOWED), evidence.reasonCodes());
        assertTrue(Files.exists(marker), "an ordinary data source must not be blocked by the terraform_remote_state check and must reach init");
    }

    // ===================== executable attestation / init-for-plan =====================

    @Test
    void wrongReportedVersionBlocksPlanBeforeInitEverRuns(@TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", "9.9.9-wrong",
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", SHOW_EMPTY);
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-wrong-version", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(List.of(RunnerReasonCode.TERRAFORM_VERSION_MISMATCH), evidence.reasonCodes());
        assertFalse(Files.exists(marker));
    }

    @Test
    void initForPlanFailureBlocksBeforePlanEverRuns(@TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        Path marker = trustedRoot.resolve("PLAN_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "exit 1\n", "touch '" + marker + "'\nexit 0\n", SHOW_EMPTY);
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-init-fail", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_PLAN_INIT_FAILED), evidence.reasonCodes());
        assertFalse(Files.exists(marker), "plan must never launch once its own init-for-plan step failed");
    }

    // ===================== detailed exit code semantics =====================

    @Test
    void planExitCodeZeroIsSuccessWithNoChanges(@TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                INIT_OK, "echo 'FAKE_PLAN_BYTES' > \"$outpath\"\nexit 0\n", SHOW_EMPTY);
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-plan-nochange", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.SUCCEEDED, evidence.processState(), evidence.reasonCodes().toString());
        assertFalse(evidence.hasChanges());
        assertNotNull(evidence.planSha256());
    }

    @Test
    void planExitCodeTwoIsSuccessWithChangesNotFailure(@TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                INIT_OK, "echo 'FAKE_PLAN_BYTES' > \"$outpath\"\nexit 2\n", SHOW_EMPTY);
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-plan-changes", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.COMMAND_REPORTED_DIFFERENCE, evidence.processState(), evidence.reasonCodes().toString());
        assertTrue(evidence.hasChanges());
        assertTrue(evidence.succeeded(), "exit code 2 must never be treated as a failure");
        assertTrue(evidence.reasonCodes().isEmpty());
    }

    @Test
    void planExitCodeOneIsAGenuineFailure(@TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED, INIT_OK, "exit 1\n", SHOW_EMPTY);
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-plan-fail", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.FAILED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_PLAN_FAILED), evidence.reasonCodes());
        assertFalse(evidence.succeeded());
    }

    @Test
    void planUnexpectedExitCodeIsTreatedAsFailure(@TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED, INIT_OK, "exit 5\n", SHOW_EMPTY);
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-plan-weird-exit", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.FAILED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_PLAN_FAILED), evidence.reasonCodes());
    }

    // ===================== state-lock / backend failure classification (security amendment) =====================

    @Test
    void initLockAlreadyHeldStderrClassifiesDeterministically(@TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "echo 'Error acquiring the state lock' 1>&2\nexit 1\n", "exit 0\n", SHOW_EMPTY);
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-lock-held", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_STATE_LOCK_FAILED), evidence.reasonCodes());
    }

    @Test
    void initLockAcquisitionTimeoutStderrClassifiesDeterministically(@TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "echo 'Error acquiring the state lock: timeout while attempting to acquire state lock' 1>&2\nexit 1\n", "exit 0\n", SHOW_EMPTY);
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-lock-timeout", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_STATE_LOCK_TIMEOUT), evidence.reasonCodes());
    }

    @Test
    void initBackendUnavailableStderrClassifiesDeterministically(@TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "echo 'Error: error configuring the backend \"local\": failed to open state file' 1>&2\nexit 1\n", "exit 0\n", SHOW_EMPTY);
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-backend-unavailable", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_STATE_BACKEND_UNAVAILABLE), evidence.reasonCodes());
    }

    @Test
    void initUnrelatedFailureStderrFallsBackToGenericInitFailure(@TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "echo 'Error: something unrelated went wrong' 1>&2\nexit 1\n", "exit 0\n", SHOW_EMPTY);
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-init-generic-fail", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_PLAN_INIT_FAILED), evidence.reasonCodes(),
                "text that does not clearly match a specific classification must never be guessed at - it falls back to the generic reason");
    }

    @Test
    void planStepLockFailureStderrClassifiesDeterministicallyToo(@TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                INIT_OK, "echo 'Error acquiring the state lock' 1>&2\nexit 1\n", SHOW_EMPTY);
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-plan-lock-held", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.FAILED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_STATE_LOCK_FAILED), evidence.reasonCodes(),
                "the same classification must apply at the plan step, not only the init-for-plan step");
    }

    @Test
    void lockTimeoutArgIsFixedAndInternallyControlledInBothInitAndPlanArgv() {
        TerraformCommandFactory factory = new TerraformCommandFactory(new TerraformProcessEnvironmentPolicy(), new TerraformInitProcessEnvironmentPolicy());
        TerraformExecutableDescriptor descriptor = new TerraformExecutableDescriptor(Path.of("/tools/terraform"), "sha", "1.6.6", Path.of("/tools"));
        ControlledTerraformCommand init = factory.initForPlanCommand(
                baseRequest("r", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), descriptor, Path.of("/work"), Duration.ofSeconds(5), Map.of());
        ControlledTerraformCommand plan = factory.planCommand(
                baseRequest("r", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), descriptor, Path.of("/work"), Path.of("/work/plan/tfplan"), Duration.ofSeconds(5), Map.of());

        assertTrue(init.argv().stream().anyMatch(a -> a.startsWith("-lock-timeout=")), "init-for-plan must set a fixed, bounded lock timeout");
        assertTrue(plan.argv().stream().anyMatch(a -> a.startsWith("-lock-timeout=")), "plan must set a fixed, bounded lock timeout");
        // Nothing in RunnerRequest can influence this value - see runnerRequestHasNoBackendOrStateField.
    }

    // ===================== plan artifact safety =====================

    @Test
    void planArtifactPathIsRunnerOwnedUnderTheWorkspace(@TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        var manager = new RunnerWorkspaceManager(workspace);
        Path planPath = manager.preparePlanArtifactPath(workspace);
        assertTrue(planPath.startsWith(workspace));
        assertEquals("tfplan", planPath.getFileName().toString());
    }

    @Test
    void preExistingSymlinkAtThePlanPathIsRejectedBeforePlanLaunches(
            @TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot, @TempDir Path outside) throws IOException {
        Files.createDirectories(workspace.resolve("plan"));
        Path secretOutside = outside.resolve("secret.tfplan");
        Files.writeString(secretOutside, "outside-content");
        Files.createSymbolicLink(workspace.resolve("plan").resolve("tfplan"), secretOutside);

        Path marker = trustedRoot.resolve("PLAN_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                INIT_OK, "touch '" + marker + "'\nexit 0\n", SHOW_EMPTY);
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-plan-symlink", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_PLAN_ARTIFACT_INVALID), evidence.reasonCodes());
        assertFalse(Files.exists(marker), "plan must never launch once the saved-plan path was rejected as unsafe");
    }

    @Test
    void planArtifactMustBeARegularFileAfterTheCommandRuns(@TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        // exits 0 ("success") but never actually writes anything to $outpath.
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED, INIT_OK, "exit 0\n", SHOW_EMPTY);
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-plan-no-artifact", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.FAILED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_PLAN_ARTIFACT_INVALID), evidence.reasonCodes());
    }

    @Test
    void planHashIsComputedFromTheExactSavedPlanBytesAndMatchesTheStoredArtifact(
            @TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                INIT_OK, "printf 'EXACT-PLAN-BYTES' > \"$outpath\"\nexit 0\n", SHOW_EMPTY);
        var artifactStore = new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts"));
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), artifactStore);

        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-plan-hash", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.SUCCEEDED, evidence.processState(), evidence.reasonCodes().toString());
        assertEquals(sha256Hex("EXACT-PLAN-BYTES".getBytes(StandardCharsets.UTF_8)), evidence.planSha256());

        var stored = artifactStore.resolve(evidence.planArtifactId());
        assertTrue(stored.isPresent());
        assertEquals(evidence.planSha256(), stored.get().metadata().planSha256());
        assertArrayEquals("EXACT-PLAN-BYTES".getBytes(StandardCharsets.UTF_8), stored.get().planBytes());
    }

    // ===================== durable plan artifact store security (security amendment) =====================

    @Test
    void traversalViaCallerSuppliedArtifactIdIsImpossible(@TempDir Path stateRoot, @TempDir Path outside) throws IOException {
        Path secretOutside = outside.resolve("secret.tfplan");
        Files.writeString(secretOutside, "outside-content");
        var store = new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts"));

        for (String hostile : List.of(
                "../secret", "../../etc/passwd", "sha256-../../../etc/passwd",
                "sha256-" + "a".repeat(64) + "/../../../etc", "/etc/passwd",
                "sha256-" + outside.resolve("secret.tfplan"))) {
            assertTrue(store.resolve(hostile).isEmpty(), "must reject as not-found: " + hostile);
            assertTrue(store.metadata(hostile).isEmpty(), "must reject as not-found: " + hostile);
        }
    }

    @Test
    void symlinkedArtifactDirectoryIsRejected(@TempDir Path stateRoot, @TempDir Path outside) throws IOException {
        Path artifactsRoot = stateRoot.resolve("artifacts");
        var store = new FileBackedTerraformPlanArtifactStore(artifactsRoot);
        TerraformPlanArtifactMetadata stored = store.store(REPOSITORY, COMMIT_SHA, ENVIRONMENT, "state-sha", "input-sha",
                "REAL-PLAN-BYTES".getBytes(StandardCharsets.UTF_8));

        // Replace the artifact directory itself with a symlink to attacker-controlled content that
        // impersonates the same planArtifactId.
        Path realArtifactDir = artifactsRoot.resolve(stored.planArtifactId());
        deleteRecursively(realArtifactDir);
        Path forgedDir = outside.resolve("forged");
        Files.createDirectories(forgedDir);
        Files.writeString(forgedDir.resolve("plan.tfplan"), "FORGED-BYTES");
        Files.writeString(forgedDir.resolve("metadata.json"),
                "{\"planArtifactId\":\"" + stored.planArtifactId() + "\",\"planSha256\":\"" + stored.planSha256()
                        + "\",\"planInputSha256\":\"input-sha\",\"repository\":\"" + REPOSITORY + "\",\"commitSha\":\"" + COMMIT_SHA
                        + "\",\"environment\":\"" + ENVIRONMENT + "\",\"stateIdentitySha256\":\"state-sha\",\"planByteSize\":12,\"storedAt\":\""
                        + Instant.now() + "\"}");
        Files.createSymbolicLink(realArtifactDir, forgedDir);

        assertTrue(store.resolve(stored.planArtifactId()).isEmpty(), "a symlinked artifact directory must never be trusted");
        assertTrue(store.metadata(stored.planArtifactId()).isEmpty(), "a symlinked artifact directory must never be trusted");
    }

    @Test
    void symlinkAncestorEscapeAtThePlanFileIsRejected(@TempDir Path stateRoot, @TempDir Path outside) throws IOException {
        Path artifactsRoot = stateRoot.resolve("artifacts");
        var store = new FileBackedTerraformPlanArtifactStore(artifactsRoot);
        TerraformPlanArtifactMetadata stored = store.store(REPOSITORY, COMMIT_SHA, ENVIRONMENT, "state-sha", "input-sha",
                "REAL-PLAN-BYTES".getBytes(StandardCharsets.UTF_8));

        Path planPath = artifactsRoot.resolve(stored.planArtifactId()).resolve("plan.tfplan");
        Path secretOutside = outside.resolve("secret.tfplan");
        Files.writeString(secretOutside, "REAL-PLAN-BYTES");
        Files.delete(planPath);
        Files.createSymbolicLink(planPath, secretOutside);

        assertTrue(store.resolve(stored.planArtifactId()).isEmpty(), "a symlinked plan file must never be trusted, even with matching bytes");
    }

    @Test
    void tamperedPlanBytesAreRejectedOnResolve(@TempDir Path stateRoot) throws IOException {
        Path artifactsRoot = stateRoot.resolve("artifacts");
        var store = new FileBackedTerraformPlanArtifactStore(artifactsRoot);
        TerraformPlanArtifactMetadata stored = store.store(REPOSITORY, COMMIT_SHA, ENVIRONMENT, "state-sha", "input-sha",
                "REAL-PLAN-BYTES".getBytes(StandardCharsets.UTF_8));

        Path planPath = artifactsRoot.resolve(stored.planArtifactId()).resolve("plan.tfplan");
        Files.write(planPath, "TAMPERED-BYTES!!".getBytes(StandardCharsets.UTF_8));

        assertTrue(store.resolve(stored.planArtifactId()).isEmpty(), "bytes that no longer match the recorded hash must never be returned");
    }

    @Test
    void metadataHashMismatchIsRejectedOnResolve(@TempDir Path stateRoot) throws IOException {
        Path artifactsRoot = stateRoot.resolve("artifacts");
        var store = new FileBackedTerraformPlanArtifactStore(artifactsRoot);
        TerraformPlanArtifactMetadata stored = store.store(REPOSITORY, COMMIT_SHA, ENVIRONMENT, "state-sha", "input-sha",
                "REAL-PLAN-BYTES".getBytes(StandardCharsets.UTF_8));

        Path metadataPath = artifactsRoot.resolve(stored.planArtifactId()).resolve("metadata.json");
        String forgedJson = Files.readString(metadataPath, StandardCharsets.UTF_8)
                .replace(stored.planSha256(), "f".repeat(64));
        Files.writeString(metadataPath, forgedJson);

        assertTrue(store.resolve(stored.planArtifactId()).isEmpty(), "a metadata planSha256 that disagrees with the actual bytes must never be trusted");
        assertTrue(store.metadata(stored.planArtifactId()).isEmpty(), "metadata() must apply the same id/hash agreement check");
    }

    @Test
    void wrongIdentityMetadataIsRejectedOnResolve(@TempDir Path stateRoot) throws IOException {
        Path artifactsRoot = stateRoot.resolve("artifacts");
        var store = new FileBackedTerraformPlanArtifactStore(artifactsRoot);
        TerraformPlanArtifactMetadata a = store.store(REPOSITORY, COMMIT_SHA, ENVIRONMENT, "state-sha", "input-sha",
                "PLAN-A-BYTES".getBytes(StandardCharsets.UTF_8));
        TerraformPlanArtifactMetadata b = store.store(REPOSITORY, COMMIT_SHA, ENVIRONMENT, "state-sha", "input-sha",
                "PLAN-B-BYTES!!!!".getBytes(StandardCharsets.UTF_8));

        // Swap metadata files between two otherwise-legitimate artifacts.
        Path metadataA = artifactsRoot.resolve(a.planArtifactId()).resolve("metadata.json");
        Path metadataB = artifactsRoot.resolve(b.planArtifactId()).resolve("metadata.json");
        String contentA = Files.readString(metadataA, StandardCharsets.UTF_8);
        String contentB = Files.readString(metadataB, StandardCharsets.UTF_8);
        Files.writeString(metadataA, contentB);
        Files.writeString(metadataB, contentA);

        assertTrue(store.resolve(a.planArtifactId()).isEmpty(), "a directory whose metadata identity belongs to a different artifact must never be trusted");
        assertTrue(store.resolve(b.planArtifactId()).isEmpty(), "a directory whose metadata identity belongs to a different artifact must never be trusted");
    }

    @Test
    void planContentIsAbsentFromMetadataAndEvidence(@TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        String secretMarker = "SUPER-SECRET-PLAN-PAYLOAD-MARKER";
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                INIT_OK, "printf '" + secretMarker + "' > \"$outpath\"\nexit 0\n", SHOW_EMPTY);
        var artifactStore = new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts"));
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), artifactStore);

        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-plan-secret", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));
        assertEquals(TerraformProcessState.SUCCEEDED, evidence.processState(), evidence.reasonCodes().toString());
        assertFalse(evidence.toString().contains(secretMarker), "RunnerEvidence/TerraformPlanEvidence must never contain plan bytes");

        var stored = artifactStore.resolve(evidence.planArtifactId());
        assertTrue(stored.isPresent());
        assertFalse(stored.get().metadata().toString().contains(secretMarker), "artifact metadata must never contain plan bytes");

        Path metadataFile = stateRoot.resolve("artifacts").resolve(evidence.planArtifactId()).resolve("metadata.json");
        assertFalse(Files.readString(metadataFile, StandardCharsets.UTF_8).contains(secretMarker), "the metadata.json sidecar must never contain plan bytes");
    }

    @Test
    void posixPermissionsAreAppliedWherePlatformSupportsThem(@TempDir Path stateRoot) throws IOException {
        org.junit.jupiter.api.Assumptions.assumeTrue(
                stateRoot.getFileSystem().supportedFileAttributeViews().contains("posix"), "POSIX permissions are not applicable on this platform");

        Path artifactsRoot = stateRoot.resolve("artifacts");
        var store = new FileBackedTerraformPlanArtifactStore(artifactsRoot);
        TerraformPlanArtifactMetadata stored = store.store(REPOSITORY, COMMIT_SHA, ENVIRONMENT, "state-sha", "input-sha",
                "REAL-PLAN-BYTES".getBytes(StandardCharsets.UTF_8));

        Path artifactDir = artifactsRoot.resolve(stored.planArtifactId());
        Path planPath = artifactDir.resolve("plan.tfplan");
        Path metadataPath = artifactDir.resolve("metadata.json");

        assertEquals("rwx------", java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(artifactsRoot)));
        assertEquals("rwx------", java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(artifactDir)));
        assertEquals("rw-------", java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(planPath)));
        assertEquals("rw-------", java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(metadataPath)));
    }

    private static void deleteRecursively(Path path) throws IOException {
        if (!Files.exists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        try (var stream = Files.walk(path)) {
            stream.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.delete(p);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            });
        }
    }

    // ===================== plan JSON / risk integration =====================

    @Test
    void showRunsAgainstTheExactSavedPlanAndExtractsChangeCounts(@TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        String showJson = """
                {"resource_changes":[
                  {"address":"aws_instance.a","type":"aws_instance","name":"a","change":{"actions":["create"],"before":null,"after":{}}},
                  {"address":"aws_instance.b","type":"aws_instance","name":"b","change":{"actions":["update"],"before":{},"after":{}}},
                  {"address":"aws_instance.c","type":"aws_instance","name":"c","change":{"actions":["delete","create"],"before":{},"after":{}}},
                  {"address":"aws_instance.d","type":"aws_instance","name":"d","change":{"actions":["delete"],"before":{},"after":null}}
                ]}
                """.replace("\n", "");
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                INIT_OK, "echo 'FAKE' > \"$outpath\"\nexit 2\n", "echo '" + showJson + "'\nexit 0\n");
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-plan-summary", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.COMMAND_REPORTED_DIFFERENCE, evidence.processState(), evidence.reasonCodes().toString());
        assertEquals(1, evidence.createCount());
        assertEquals(1, evidence.updateCount());
        assertEquals(1, evidence.replaceCount());
        assertEquals(1, evidence.destroyCount());

        // RiskEngine reuse: the extracted summary is consumable by the existing engine unchanged.
        var summary = new com.iacagent.iacagent.PlanJsonParser().parse(showJson);
        var risk = new com.iacagent.iacagent.RiskEngine().assess(summary, ENVIRONMENT);
        assertNotNull(risk);
    }

    @Test
    void malformedShowJsonBlocksThePlanAttempt(@TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                INIT_OK, "echo 'FAKE' > \"$outpath\"\nexit 0\n", "echo '{ not valid'\nexit 0\n");
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-plan-malformed-show", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.FAILED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_OUTPUT_INVALID_JSON), evidence.reasonCodes());
    }

    // ===================== plan input identity =====================

    @Test
    void differentStateTargetsProduceDifferentPlanInputIdentities() {
        String a = TerraformPlanInputIdentity.computeSha256("cfg", "state-a", "lock", "exe", "1.6.6", "nonprod", "MODE", List.of());
        String b = TerraformPlanInputIdentity.computeSha256("cfg", "state-b", "lock", "exe", "1.6.6", "nonprod", "MODE", List.of());
        assertNotEquals(a, b);
    }

    @Test
    void differentProviderLockHashesProduceDifferentPlanInputIdentities() {
        String a = TerraformPlanInputIdentity.computeSha256("cfg", "state", "lock-a", "exe", "1.6.6", "nonprod", "MODE", List.of());
        String b = TerraformPlanInputIdentity.computeSha256("cfg", "state", "lock-b", "exe", "1.6.6", "nonprod", "MODE", List.of());
        assertNotEquals(a, b);
    }

    @Test
    void differentExecutableHashesProduceDifferentPlanInputIdentities() {
        String a = TerraformPlanInputIdentity.computeSha256("cfg", "state", "lock", "exe-a", "1.6.6", "nonprod", "MODE", List.of());
        String b = TerraformPlanInputIdentity.computeSha256("cfg", "state", "lock", "exe-b", "1.6.6", "nonprod", "MODE", List.of());
        assertNotEquals(a, b);
    }

    @Test
    void differentEnvironmentsProduceDifferentPlanInputIdentities() {
        String a = TerraformPlanInputIdentity.computeSha256("cfg", "state", "lock", "exe", "1.6.6", "nonprod", "MODE", List.of());
        String b = TerraformPlanInputIdentity.computeSha256("cfg", "state", "lock", "exe", "1.6.6", "prod", "MODE", List.of());
        assertNotEquals(a, b);
    }

    @Test
    void differentVariableInputsProduceDifferentPlanInputIdentities() {
        String a = TerraformPlanInputIdentity.computeSha256("cfg", "state", "lock", "exe", "1.6.6", "nonprod", "MODE", List.of());
        String b = TerraformPlanInputIdentity.computeSha256("cfg", "state", "lock", "exe", "1.6.6", "nonprod", "MODE",
                List.of(new TerraformVariableInput("region", "\"us-east-1\"", false)));
        assertNotEquals(a, b);
    }

    @Test
    void sameInputsProduceTheSamePlanInputIdentity() {
        String a = TerraformPlanInputIdentity.computeSha256("cfg", "state", "lock", "exe", "1.6.6", "nonprod", "MODE", List.of());
        String b = TerraformPlanInputIdentity.computeSha256("cfg", "state", "lock", "exe", "1.6.6", "nonprod", "MODE", List.of());
        assertEquals(a, b);
    }

    // ===================== credential redaction =====================

    private static final class FakeSecretCredentialProvider implements TerraformCredentialProvider {
        static final String SECRET_VALUE = "super-secret-token-do-not-leak";

        @Override
        public TerraformCredentialMaterial obtain(RunnerRequest request, TerraformStateIdentity stateIdentity) {
            return new TerraformCredentialMaterial(Map.of("FAKE_CLOUD_TOKEN", SECRET_VALUE), "fake:test-only");
        }
    }

    @Test
    void credentialValuesNeverAppearInEvidenceOrItsSerializedForm(@TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                INIT_OK, "echo 'FAKE' > \"$outpath\"\nexit 0\n", SHOW_EMPTY);
        var coordinator = coordinatorForPlan(binary, trustedRoot, workspace, new ReferenceLocalBackendResolver(stateRoot),
                new FakeSecretCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        TerraformPlanEvidence evidence = coordinator.executePlan(
                baseRequest("r-plan-credential", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.SUCCEEDED, evidence.processState(), evidence.reasonCodes().toString());
        assertEquals("fake:test-only", evidence.credentialSourceIdentifier());
        assertFalse(evidence.toString().contains(FakeSecretCredentialProvider.SECRET_VALUE),
                "TerraformPlanEvidence has no field for credential material at all - its toString() must never contain a secret value");
        // JSON-serialization redaction is proven in Phase2b5JdbcTests (same package as
        // TerraformPlanEvidenceJson, which is package-private).
    }

    @Test
    void noOpCredentialProviderSuppliesNoEnvironmentVariablesAndAnHonestSourceIdentifier() {
        var provider = new NoOpTerraformCredentialProvider();
        var material = provider.obtain(baseRequest("r", "a", "s", "ap", RunnerOperation.TERRAFORM_PLAN),
                new TerraformStateIdentity("local", "reference-local", ENVIRONMENT, "key"));
        assertTrue(material.environmentVariables().isEmpty());
        assertEquals("none:local-backend-reference", material.sourceIdentifier());
    }

    // ===================== end-to-end through ControlledRunner =====================

    @Test
    void terraformPlanSucceedsEndToEndThroughControlledRunner(@TempDir Path root, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String configSha = sha256Hex(PROVIDERLESS_CONFIG);
        String approvalId = issueValidApproval(repo, configSha);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(new StoredArtifact("config-1", PROVIDERLESS_CONFIG, PROVIDERLESS_CONFIG.length, configSha, new ArtifactProvenance("test")));
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                INIT_OK, "echo 'FAKE' > \"$outpath\"\nexit 0\n", SHOW_EMPTY);
        ControlledRunner runner = runnerWithPlan(root, repo, artifactStore, binary, trustedRoot, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));

        RunnerEvidence evidence = runner.execute(baseRequest("req-e2e-plan", "config-1", configSha, approvalId, RunnerOperation.TERRAFORM_PLAN));

        assertEquals(RunnerState.TERRAFORM_PROCESS_COMPLETED, evidence.finalState());
        assertNotNull(evidence.terraformPlanEvidence());
        assertEquals(TerraformProcessState.SUCCEEDED, evidence.terraformPlanEvidence().processState());
        assertNull(evidence.terraformProcessEvidence());
        assertNull(evidence.terraformInitEvidence());
        assertNull(evidence.terraformValidateEvidence());
        assertNull(evidence.terraformProviderSchemaEvidence());
    }

    @Test
    void duplicateTerraformPlanRequestStillBlocksViaTheExistingReplayProtection(@TempDir Path root, @TempDir Path trustedRoot, @TempDir Path stateRoot) throws IOException {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String configSha = sha256Hex(PROVIDERLESS_CONFIG);
        String approvalId = issueValidApproval(repo, configSha);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(new StoredArtifact("config-1", PROVIDERLESS_CONFIG, PROVIDERLESS_CONFIG.length, configSha, new ArtifactProvenance("test")));
        Path binary = FakeExecutables.terraformPlanStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                INIT_OK, "echo 'FAKE' > \"$outpath\"\nexit 0\n", SHOW_EMPTY);
        ControlledRunner runner = runnerWithPlan(root, repo, artifactStore, binary, trustedRoot, new ReferenceLocalBackendResolver(stateRoot),
                new NoOpTerraformCredentialProvider(), new FileBackedTerraformPlanArtifactStore(stateRoot.resolve("artifacts")));
        RunnerRequest request = baseRequest("req-e2e-plan-dup", "config-1", configSha, approvalId, RunnerOperation.TERRAFORM_PLAN);

        RunnerEvidence first = runner.execute(request);
        RunnerEvidence second = runner.execute(request);

        assertEquals(RunnerState.TERRAFORM_PROCESS_COMPLETED, first.finalState());
        assertEquals(RunnerState.BLOCKED, second.finalState());
        assertEquals(List.of(RunnerReasonCode.DUPLICATE_RUNNER_REQUEST), second.reasonCodes());
    }

    @Test
    void runnerNotWiredForPlanBlocksRatherThanThrowing(@TempDir Path root) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String planSha = sha256Hex(PROVIDERLESS_CONFIG);
        String approvalId = issueValidApproval(repo, planSha);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(new StoredArtifact("config-1", PROVIDERLESS_CONFIG, PROVIDERLESS_CONFIG.length, planSha, new ArtifactProvenance("test")));
        ControlledRunner runner = new ControlledRunner(
                new StaticRunnerIdentityProvider(trustedIdentity()),
                ALLOWED_RUNNER_CLASSES,
                new RepositoryBackedApprovalProvider(repo),
                artifactStore,
                new StaticRunnerToolchainContext(TERRAFORM_VERSION_EXPECTED, PROVIDER_LOCK_HASH),
                new RunnerWorkspaceManager(root),
                new InMemoryRunnerLedgerRepository(),
                new MutableClock(NOW));

        RunnerEvidence evidence = runner.execute(baseRequest("req-not-wired", "config-1", planSha, approvalId, RunnerOperation.TERRAFORM_PLAN));

        assertEquals(RunnerState.BLOCKED, evidence.finalState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_OPERATION_NOT_ALLOWED), evidence.reasonCodes());
    }

    // ===================== helpers =====================

    private ControlledTerraformOperationCoordinator coordinatorForPlan(
            Path binary, Path trustedRoot, Path workspace, TrustedBackendResolver backendResolver,
            TerraformCredentialProvider credentialProvider, TerraformPlanArtifactStore planArtifactStore) throws IOException {
        var provider = new HostConfiguredTerraformExecutableProvider(binary, FakeExecutables.sha256Hex(binary), TERRAFORM_VERSION_EXPECTED, trustedRoot, List.of());
        return new ControlledTerraformOperationCoordinator(
                provider,
                new TerraformCommandFactory(new TerraformProcessEnvironmentPolicy(), new TerraformInitProcessEnvironmentPolicy()),
                new ControlledTerraformProcess(),
                new RunnerWorkspaceManager(workspace),
                Duration.ofSeconds(10), Duration.ofSeconds(10), Duration.ofSeconds(10),
                Duration.ofSeconds(10), Duration.ofSeconds(10), Duration.ofSeconds(10),
                TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY,
                backendResolver, credentialProvider, planArtifactStore,
                Duration.ofSeconds(10), Duration.ofSeconds(10));
    }

    private ControlledRunner runnerWithPlan(Path root, InMemoryApprovalRepository repo, InMemoryRunnerArtifactStore artifactStore, Path binary, Path trustedRoot,
                                             TrustedBackendResolver backendResolver, TerraformCredentialProvider credentialProvider, TerraformPlanArtifactStore planArtifactStore) throws IOException {
        var provider = new HostConfiguredTerraformExecutableProvider(binary, FakeExecutables.sha256Hex(binary), TERRAFORM_VERSION_EXPECTED, trustedRoot, List.of(root));
        var coordinator = new ControlledTerraformOperationCoordinator(
                provider,
                new TerraformCommandFactory(new TerraformProcessEnvironmentPolicy(), new TerraformInitProcessEnvironmentPolicy()),
                new ControlledTerraformProcess(),
                new RunnerWorkspaceManager(root),
                Duration.ofSeconds(10), Duration.ofSeconds(10), Duration.ofSeconds(10),
                Duration.ofSeconds(10), Duration.ofSeconds(10), Duration.ofSeconds(10),
                TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY,
                backendResolver, credentialProvider, planArtifactStore,
                Duration.ofSeconds(10), Duration.ofSeconds(10));
        return new ControlledRunner(
                new StaticRunnerIdentityProvider(trustedIdentity()),
                ALLOWED_RUNNER_CLASSES,
                new RepositoryBackedApprovalProvider(repo),
                artifactStore,
                new StaticRunnerToolchainContext(TERRAFORM_VERSION_EXPECTED, PROVIDER_LOCK_HASH),
                new RunnerWorkspaceManager(root),
                new InMemoryRunnerLedgerRepository(),
                new MutableClock(NOW),
                coordinator);
    }
}
