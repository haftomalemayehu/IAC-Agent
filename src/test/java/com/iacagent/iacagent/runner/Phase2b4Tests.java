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
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 2B-4 tests: controlled provider/backend initialization and validation - the
 * {@code TERRAFORM_INIT}/{@code TERRAFORM_VALIDATE}/{@code TERRAFORM_PROVIDERS_SCHEMA} operations.
 * Covers backend-mode enforcement (always {@code -backend=false}, no caller-supplied backend
 * arguments possible at all), provider/module source policy screening (before any process is ever
 * launched), lockfile integrity (symlink defense, unchanged/changed/missing handling), the
 * init-then-validate/schema sequencing (never runs its own command without a successful, freshly-run
 * init for the identical staged configuration), and the network-requirement evidence model.
 *
 * <p>Fake POSIX shell-script executables ({@link FakeExecutables#terraformInitStub}) stand in for
 * Terraform - per the Phase 2B-4 authorization's own guidance, no test here depends on downloading
 * Terraform, network access, or a pinned-Terraform-version-specific {@code -lockfile=readonly}
 * behavior; init/validate/providers-schema outcomes are entirely fixture-controlled.
 */
class Phase2b4Tests {

    private static final Instant NOW = Instant.parse("2026-09-11T00:00:00Z");
    private static final String REPOSITORY = "owner/repository";
    private static final String COMMIT_SHA = "c".repeat(40);
    private static final String ENVIRONMENT = "nonprod";
    private static final String TERRAFORM_VERSION_EXPECTED = "1.6.6";
    private static final String PROVIDER_LOCK_HASH = "sha256:lock-abc";
    private static final Set<String> ALLOWED_RUNNER_CLASSES = Set.of("terraform-test-runner");

    private static final byte[] PROVIDERLESS_CONFIG = "resource \"terraform_data\" \"x\" {}\n".getBytes(StandardCharsets.UTF_8);

    private static final byte[] ALLOWED_PROVIDER_CONFIG = ("""
            terraform {
              required_providers {
                aws = {
                  source = "registry.terraform.io/hashicorp/aws"
                }
              }
            }
            """).getBytes(StandardCharsets.UTF_8);

    private static final byte[] DISALLOWED_PROVIDER_CONFIG = ("""
            terraform {
              required_providers {
                evil = {
                  source = "example.com/evil/aws"
                }
              }
            }
            """).getBytes(StandardCharsets.UTF_8);

    private static final byte[] DISALLOWED_GIT_MODULE_CONFIG = ("""
            module "foo" {
              source = "github.com/evil/module"
            }
            """).getBytes(StandardCharsets.UTF_8);

    private static final byte[] LOCAL_MODULE_CONFIG = ("""
            module "foo" {
              source = "./modules/foo"
            }
            """).getBytes(StandardCharsets.UTF_8);

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

    private static List<TerraformConfigIdentity.NamedConfigFile> singleFile(byte[] content) {
        return List.of(new TerraformConfigIdentity.NamedConfigFile("main.tf", content));
    }

    private RunnerRequest baseRequest(String requestId, String artifactId, String planSha256, String approvalId, RunnerOperation operation) {
        return new RunnerRequest(requestId, REPOSITORY, COMMIT_SHA, ENVIRONMENT, artifactId, planSha256,
                TERRAFORM_VERSION_EXPECTED, PROVIDER_LOCK_HASH, approvalId, operation);
    }

    // ===================== structural =====================

    @Test
    void runnerRequestHasNoFieldThatCouldWidenOrSupplySourcePolicy() {
        List<String> forbiddenComponentNamesLower = List.of("sourcepolicy", "allowedprovider", "allowedmodule", "backendmode", "cliconfig", "pluginpath");
        for (RecordComponent component : RunnerRequest.class.getRecordComponents()) {
            String lower = component.getName().toLowerCase();
            for (String forbidden : forbiddenComponentNamesLower) {
                assertFalse(lower.contains(forbidden), "RunnerRequest must not carry a field that could widen source/backend policy: " + component.getName());
            }
        }
    }

    @Test
    void terraformCommandFactoryBuildsExactlyTheAuthorizedCommandsAndNothingElse() {
        // Phase 2B-5 added initForPlanCommand/planCommand alongside the six Phase 2B-3/2B-4 methods -
        // see Phase2b5Tests for the PLAN-specific argv/structural coverage.
        Set<String> commandMethodNames = java.util.Arrays.stream(TerraformCommandFactory.class.getDeclaredMethods())
                .filter(m -> java.lang.reflect.Modifier.isPublic(m.getModifiers()))
                .map(java.lang.reflect.Method::getName)
                .collect(java.util.stream.Collectors.toSet());
        assertEquals(Set.of("versionCommand", "fmtCheckCommand", "showPlanJsonCommand", "initCommand", "validateCommand", "providersSchemaCommand",
                "initForPlanCommand", "planCommand"), commandMethodNames);
    }

    @Test
    void terraformBackendModeHasExactlyThreeValuesAndLocalOnlyIsTheOnlyOneThisPhaseRuns() {
        assertEquals(Set.of("LOCAL_ONLY", "REMOTE_READONLY_INIT", "REMOTE_ALLOWED"),
                java.util.Arrays.stream(TerraformBackendMode.values()).map(Enum::name).collect(java.util.stream.Collectors.toSet()));
    }

    // ===================== backend safety =====================

    @Test
    void initCommandArgvAlwaysUsesBackendFalseAndCannotAcceptBackendConfig() {
        TerraformCommandFactory factory = new TerraformCommandFactory(new TerraformProcessEnvironmentPolicy(), new TerraformInitProcessEnvironmentPolicy());
        TerraformExecutableDescriptor descriptor = new TerraformExecutableDescriptor(Path.of("/tools/terraform"), "sha", "1.6.6", Path.of("/tools"));
        ControlledTerraformCommand command = factory.initCommand(baseRequest("r", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), descriptor, Path.of("/work"), Duration.ofSeconds(5));

        assertTrue(command.argv().contains("-backend=false"));
        for (String forbidden : List.of("-backend-config", "-reconfigure", "-migrate-state", "-force-copy", "-upgrade")) {
            assertFalse(command.argv().stream().anyMatch(a -> a.startsWith(forbidden)), forbidden + " must never appear in init argv");
        }
    }

    @Test
    void initCommandArgvIncludesLockfileReadonly() {
        TerraformCommandFactory factory = new TerraformCommandFactory(new TerraformProcessEnvironmentPolicy(), new TerraformInitProcessEnvironmentPolicy());
        TerraformExecutableDescriptor descriptor = new TerraformExecutableDescriptor(Path.of("/tools/terraform"), "sha", "1.6.6", Path.of("/tools"));
        ControlledTerraformCommand command = factory.initCommand(baseRequest("r", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), descriptor, Path.of("/work"), Duration.ofSeconds(5));

        assertTrue(command.argv().contains("-lockfile=readonly"));
    }

    @Test
    void backendModeViolationBlocksBeforeAnyProcessLaunch(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.REMOTE_ALLOWED);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-backend", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_BACKEND_MODE_UNSAFE), evidence.reasonCodes());
        assertFalse(Files.exists(marker), "init must never have actually run once the backend mode was rejected");
    }

    // ===================== provider/module source policy =====================

    @Test
    void allowedProviderSourceIsAcceptedAndInitProceeds(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "echo 'lock' > .terraform.lock.hcl\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-allowed-provider", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace, singleFile(ALLOWED_PROVIDER_CONFIG));

        assertEquals(TerraformProcessState.SUCCEEDED, evidence.processState(), evidence.reasonCodes().toString());
        assertEquals(List.of("registry.terraform.io/hashicorp/aws"), evidence.providerSourcesRequested());
        assertEquals(TerraformNetworkRequirement.PROVIDER_REGISTRY_ONLY, evidence.networkRequirement());
    }

    @Test
    void disallowedProviderSourceBlocksBeforeInitEverRuns(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-bad-provider", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace, singleFile(DISALLOWED_PROVIDER_CONFIG));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_PROVIDER_SOURCE_UNTRUSTED), evidence.reasonCodes());
        assertFalse(Files.exists(marker), "init must never have actually run once the provider source was rejected");
    }

    @Test
    void disallowedGitModuleSourceBlocksBeforeInitEverRuns(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-bad-module", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace, singleFile(DISALLOWED_GIT_MODULE_CONFIG));

        // Amendment: ANY module block blocks unconditionally now (TERRAFORM_MODULE_DEPENDENCY_GRAPH_UNRESOLVED),
        // regardless of whether TerraformSourcePolicy would separately have rejected this particular
        // source - module execution is categorically deferred to a later phase (see docs).
        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_MODULE_DEPENDENCY_GRAPH_UNRESOLVED), evidence.reasonCodes());
        assertFalse(Files.exists(marker));
    }

    @Test
    void localModuleBlocksRegardlessOfSourcePolicy(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-local-module", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace, singleFile(LOCAL_MODULE_CONFIG));

        assertEquals(List.of(RunnerReasonCode.TERRAFORM_MODULE_DEPENDENCY_GRAPH_UNRESOLVED), evidence.reasonCodes());
        assertFalse(Files.exists(marker));
    }

    @Test
    void localModuleStillBlocksEvenWhenAPermissivePolicyWouldOtherwiseAllowIt(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        // A policy that WOULD allow local modules, to prove the module-presence gate runs regardless.
        TerraformSourcePolicy allowLocal = new TerraformSourcePolicy(Set.of(), Set.of(), true, false, true);
        assertTrue(allowLocal.isModuleSourceAllowed("./modules/foo"), "test setup: this policy must actually permit the local module source");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, allowLocal, TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-local-module-ok", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace, singleFile(LOCAL_MODULE_CONFIG));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_MODULE_DEPENDENCY_GRAPH_UNRESOLVED), evidence.reasonCodes());
        assertFalse(Files.exists(marker), "init must never launch for a module block, even one a permissive policy would allow");
    }

    // ===================== lockfile discipline =====================

    @Test
    void symlinkAtTheLockfilePathIsRejectedBeforeInitEverRuns(@TempDir Path workspace, @TempDir Path trustedRoot, @TempDir Path outside) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path secretOutside = outside.resolve("secret.hcl");
        Files.writeString(secretOutside, "outside-content");
        Files.createSymbolicLink(workspace.resolve(".terraform.lock.hcl"), secretOutside);
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-symlink-lock", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_LOCKFILE_INVALID), evidence.reasonCodes());
        assertFalse(Files.exists(marker), "init must never have actually run once the lockfile path was rejected as unsafe");
    }

    @Test
    void unchangedLockfileContentSucceeds(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Files.writeString(workspace.resolve(".terraform.lock.hcl"), "original\n");
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "echo 'original' > .terraform.lock.hcl\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-lock-unchanged", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.SUCCEEDED, evidence.processState(), evidence.reasonCodes().toString());
        assertNotNull(evidence.lockfileHashBefore());
        assertEquals(evidence.lockfileHashBefore(), evidence.lockfileHashAfter());
    }

    @Test
    void unexpectedLockfileMutationBlocksEvenOnASuccessfulExitCode(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Files.writeString(workspace.resolve(".terraform.lock.hcl"), "original\n");
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "echo 'modified' > .terraform.lock.hcl\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-lock-changed", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.FAILED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_LOCKFILE_CHANGED), evidence.reasonCodes());
        assertNotEquals(evidence.lockfileHashBefore(), evidence.lockfileHashAfter());
    }

    @Test
    void missingLockfileAfterAProviderDeclaringSuccessfulInitIsBlocked(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED, "exit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-lock-missing", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace, singleFile(ALLOWED_PROVIDER_CONFIG));

        assertEquals(TerraformProcessState.FAILED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_LOCKFILE_MISSING), evidence.reasonCodes());
    }

    @Test
    void providerlessConfigWithNoLockfileAtAllSucceeds(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED, "exit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-no-lock-needed", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.SUCCEEDED, evidence.processState(), evidence.reasonCodes().toString());
        assertNull(evidence.lockfileHashBefore());
        assertNull(evidence.lockfileHashAfter());
        assertEquals(TerraformNetworkRequirement.NONE, evidence.networkRequirement());
    }

    // ===================== init: process-boundary interpretation =====================

    @Test
    void wrongReportedVersionBlocksInitBeforeItEverRuns(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", "9.9.9-wrong",
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-wrong-version", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_VERSION_MISMATCH), evidence.reasonCodes());
        assertFalse(Files.exists(marker), "init must never have actually run once version verification failed");
    }

    @Test
    void initExitingNonzeroIsRecordedAsAGenuineInitFailure(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED, "exit 1\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-init-fail", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.FAILED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_INIT_FAILED), evidence.reasonCodes());
    }

    // ===================== validate =====================

    @Test
    void validateNeverRunsItsOwnCommandWithoutASuccessfulInternalInit(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path marker = trustedRoot.resolve("VALIDATE_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "exit 0\n", "touch '" + marker + "'\necho '{\"valid\":true,\"error_count\":0,\"warning_count\":0,\"diagnostics\":[]}'\nexit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformValidateEvidence evidence = coordinator.executeValidate(
                baseRequest("r-validate-no-init", "a", "s", "ap", RunnerOperation.TERRAFORM_VALIDATE), trustedIdentity(), workspace, singleFile(DISALLOWED_PROVIDER_CONFIG));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_INIT_REQUIRED), evidence.reasonCodes());
        assertFalse(evidence.initEvidence().succeeded());
        assertFalse(Files.exists(marker), "validate must never have actually run without a successful init");
    }

    @Test
    void validConfigurationParsesAsValid(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "exit 0\n", "echo '{\"valid\":true,\"error_count\":0,\"warning_count\":0,\"diagnostics\":[]}'\nexit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformValidateEvidence evidence = coordinator.executeValidate(
                baseRequest("r-validate-ok", "a", "s", "ap", RunnerOperation.TERRAFORM_VALIDATE), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.SUCCEEDED, evidence.processState());
        assertEquals(Boolean.TRUE, evidence.valid());
        assertEquals(0, evidence.errorCount());
        assertTrue(evidence.initEvidence().succeeded());
        assertEquals(evidence.initEvidence().configSha256(), evidence.configSha256());
    }

    @Test
    void invalidConfigurationIsADeterministicNonFailureOutcomeWithDiagnosticFingerprints(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        String diagnosticsJson = "{\"valid\":false,\"error_count\":1,\"warning_count\":0,\"diagnostics\":"
                + "[{\"severity\":\"error\",\"summary\":\"Unsupported argument\",\"detail\":\"An argument named X is not expected here.\"}]}";
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "exit 0\n", "echo '" + diagnosticsJson + "'\nexit 1\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformValidateEvidence evidence = coordinator.executeValidate(
                baseRequest("r-validate-invalid", "a", "s", "ap", RunnerOperation.TERRAFORM_VALIDATE), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.COMMAND_REPORTED_DIFFERENCE, evidence.processState());
        assertEquals(Boolean.FALSE, evidence.valid());
        assertEquals(1, evidence.errorCount());
        assertEquals(1, evidence.diagnosticFingerprints().size());
        assertTrue(evidence.reasonCodes().isEmpty(), "an invalid config is a legitimate outcome, never a failure reason");
    }

    @Test
    void malformedValidateJsonBlocks(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "exit 0\n", "echo '{ not valid json'\nexit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformValidateEvidence evidence = coordinator.executeValidate(
                baseRequest("r-validate-malformed", "a", "s", "ap", RunnerOperation.TERRAFORM_VALIDATE), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.FAILED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_VALIDATE_OUTPUT_INVALID), evidence.reasonCodes());
    }

    // ===================== providers schema =====================

    @Test
    void providersSchemaNeverRunsItsOwnCommandWithoutASuccessfulInternalInit(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path marker = trustedRoot.resolve("SCHEMA_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "exit 0\n", "exit 0\n", "touch '" + marker + "'\necho '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformProviderSchemaEvidence evidence = coordinator.executeProvidersSchema(
                baseRequest("r-schema-no-init", "a", "s", "ap", RunnerOperation.TERRAFORM_PROVIDERS_SCHEMA), trustedIdentity(), workspace, singleFile(DISALLOWED_PROVIDER_CONFIG));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_INIT_REQUIRED), evidence.reasonCodes());
        assertFalse(Files.exists(marker));
    }

    @Test
    void schemaJsonParsesAndBindsProviderIdentitiesAndConfigLockfileTerraformIdentity(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        String schemaJson = "{\"format_version\":\"1.0\",\"provider_schemas\":{\"registry.terraform.io/hashicorp/aws\":{}}}";
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "echo 'lock' > .terraform.lock.hcl\nexit 0\n", "exit 0\n", "echo '" + schemaJson + "'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformProviderSchemaEvidence evidence = coordinator.executeProvidersSchema(
                baseRequest("r-schema-ok", "a", "s", "ap", RunnerOperation.TERRAFORM_PROVIDERS_SCHEMA), trustedIdentity(), workspace, singleFile(ALLOWED_PROVIDER_CONFIG));

        assertEquals(TerraformProcessState.SUCCEEDED, evidence.processState(), evidence.reasonCodes().toString());
        assertEquals(List.of("registry.terraform.io/hashicorp/aws"), evidence.providerSourceIdentities());
        assertEquals(evidence.initEvidence().configSha256(), evidence.configSha256());
        assertEquals(evidence.initEvidence().lockfileHashAfter(), evidence.lockfileHash());
        assertEquals(TERRAFORM_VERSION_EXPECTED, evidence.terraformVersionObserved());
        assertNotNull(evidence.schemaJsonSha256());
        assertTrue(evidence.schemaJsonSize() > 0);
    }

    @Test
    void malformedProvidersSchemaJsonBlocks(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "exit 0\n", "exit 0\n", "echo '{ not valid'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformProviderSchemaEvidence evidence = coordinator.executeProvidersSchema(
                baseRequest("r-schema-malformed", "a", "s", "ap", RunnerOperation.TERRAFORM_PROVIDERS_SCHEMA), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.FAILED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_PROVIDER_SCHEMA_OUTPUT_INVALID), evidence.reasonCodes());
    }

    // ===================== configuration identity =====================

    @Test
    void differentConfigContentAlwaysProducesADifferentConfigIdentityAndAFreshInit(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED, "exit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence first = coordinator.executeInit(
                baseRequest("r-identity-1", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));
        TerraformInitEvidence second = coordinator.executeInit(
                baseRequest("r-identity-2", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace, singleFile(ALLOWED_PROVIDER_CONFIG));

        assertNotEquals(first.configSha256(), second.configSha256());
    }

    // ===================== end-to-end through ControlledRunner (no bypass) =====================

    @Test
    void terraformInitSucceedsEndToEndThroughControlledRunner(@TempDir Path root, @TempDir Path trustedRoot) throws IOException {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String configSha = sha256Hex(PROVIDERLESS_CONFIG);
        String approvalId = issueValidApproval(repo, configSha);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(new StoredArtifact("config-1", PROVIDERLESS_CONFIG, PROVIDERLESS_CONFIG.length, configSha, new ArtifactProvenance("test")));
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED, "exit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        ControlledRunner runner = runnerWithTerraform(root, repo, artifactStore, binary, trustedRoot);

        RunnerEvidence evidence = runner.execute(baseRequest("req-e2e-init", "config-1", configSha, approvalId, RunnerOperation.TERRAFORM_INIT));

        assertEquals(RunnerState.TERRAFORM_PROCESS_COMPLETED, evidence.finalState());
        assertNotNull(evidence.terraformInitEvidence());
        assertEquals(TerraformProcessState.SUCCEEDED, evidence.terraformInitEvidence().processState());
        assertNull(evidence.terraformProcessEvidence());
        assertNull(evidence.terraformValidateEvidence());
        assertNull(evidence.terraformProviderSchemaEvidence());
    }

    @Test
    void terraformValidateSucceedsEndToEndThroughControlledRunner(@TempDir Path root, @TempDir Path trustedRoot) throws IOException {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String configSha = sha256Hex(PROVIDERLESS_CONFIG);
        String approvalId = issueValidApproval(repo, configSha);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(new StoredArtifact("config-1", PROVIDERLESS_CONFIG, PROVIDERLESS_CONFIG.length, configSha, new ArtifactProvenance("test")));
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "exit 0\n", "echo '{\"valid\":true,\"error_count\":0,\"warning_count\":0,\"diagnostics\":[]}'\nexit 0\n", "echo '{}'\nexit 0\n");
        ControlledRunner runner = runnerWithTerraform(root, repo, artifactStore, binary, trustedRoot);

        RunnerEvidence evidence = runner.execute(baseRequest("req-e2e-validate", "config-1", configSha, approvalId, RunnerOperation.TERRAFORM_VALIDATE));

        assertEquals(RunnerState.TERRAFORM_PROCESS_COMPLETED, evidence.finalState());
        assertNotNull(evidence.terraformValidateEvidence());
        assertEquals(Boolean.TRUE, evidence.terraformValidateEvidence().valid());
        assertTrue(evidence.terraformValidateEvidence().initEvidence().succeeded());
    }

    @Test
    void duplicateTerraformInitRequestStillBlocksViaTheExistingReplayProtection(@TempDir Path root, @TempDir Path trustedRoot) throws IOException {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String configSha = sha256Hex(PROVIDERLESS_CONFIG);
        String approvalId = issueValidApproval(repo, configSha);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(new StoredArtifact("config-1", PROVIDERLESS_CONFIG, PROVIDERLESS_CONFIG.length, configSha, new ArtifactProvenance("test")));
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED, "exit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        ControlledRunner runner = runnerWithTerraform(root, repo, artifactStore, binary, trustedRoot);
        RunnerRequest request = baseRequest("req-e2e-init-dup", "config-1", configSha, approvalId, RunnerOperation.TERRAFORM_INIT);

        RunnerEvidence first = runner.execute(request);
        RunnerEvidence second = runner.execute(request);

        assertEquals(RunnerState.TERRAFORM_PROCESS_COMPLETED, first.finalState());
        assertEquals(RunnerState.BLOCKED, second.finalState());
        assertEquals(List.of(RunnerReasonCode.DUPLICATE_RUNNER_REQUEST), second.reasonCodes());
    }

    // ===================== security amendment: parser-backed source extraction =====================

    @Test
    void multilineRequiredProvidersSourceIsExtracted() {
        String config = """
                terraform {
                  required_providers {
                    aws = {
                      source  = "registry.terraform.io/hashicorp/aws"
                      version = "~> 5.0"
                    }
                  }
                }

                resource "terraform_data" "x" {}
                """;
        TerraformConfigSourceManifest manifest = TerraformConfigSourceExtractor.extract(singleFile(config.getBytes(StandardCharsets.UTF_8)));
        assertEquals(List.of("registry.terraform.io/hashicorp/aws"), manifest.providerSources());
    }

    @Test
    void unusualWhitespaceAndCompactLayoutIsStillParsedCorrectly() {
        String config = "terraform{required_providers{aws={source=\"registry.terraform.io/hashicorp/aws\"}}}\n"
                + "module\t\"foo\"\t{\n\tsource\t=\t\"registry.terraform.io/some/module\"\n}\n";
        TerraformConfigSourceManifest manifest = TerraformConfigSourceExtractor.extract(singleFile(config.getBytes(StandardCharsets.UTF_8)));
        assertEquals(List.of("registry.terraform.io/hashicorp/aws"), manifest.providerSources());
        assertEquals(List.of("registry.terraform.io/some/module"), manifest.moduleSources());
    }

    @Test
    void multipleProviderRequirementsAreAllExtracted() {
        String config = """
                terraform {
                  required_providers {
                    aws = {
                      source = "registry.terraform.io/hashicorp/aws"
                    }
                    random = {
                      source = "registry.terraform.io/hashicorp/random"
                    }
                  }
                }
                """;
        TerraformConfigSourceManifest manifest = TerraformConfigSourceExtractor.extract(singleFile(config.getBytes(StandardCharsets.UTF_8)));
        assertEquals(Set.of("registry.terraform.io/hashicorp/aws", "registry.terraform.io/hashicorp/random"), Set.copyOf(manifest.providerSources()));
    }

    @Test
    void providerRequirementWithNoExplicitSourceGetsTheDocumentedHashicorpDefault() {
        String config = """
                terraform {
                  required_providers {
                    aws = {
                      version = "~> 5.0"
                    }
                  }
                }
                """;
        TerraformConfigSourceManifest manifest = TerraformConfigSourceExtractor.extract(singleFile(config.getBytes(StandardCharsets.UTF_8)));
        assertEquals(List.of("registry.terraform.io/hashicorp/aws"), manifest.providerSources());
    }

    @Test
    void tfJsonProviderDeclarationIsExtracted() {
        String json = """
                {
                  "terraform": {
                    "required_providers": {
                      "aws": { "source": "registry.terraform.io/hashicorp/aws" }
                    }
                  }
                }
                """;
        TerraformConfigSourceManifest manifest = TerraformConfigSourceExtractor.extract(
                List.of(new TerraformConfigIdentity.NamedConfigFile("main.tf.json", json.getBytes(StandardCharsets.UTF_8))));
        assertEquals(List.of("registry.terraform.io/hashicorp/aws"), manifest.providerSources());
    }

    @Test
    void tfJsonModuleDeclarationIsExtracted() {
        String json = """
                {
                  "module": {
                    "foo": { "source": "registry.terraform.io/some/module" }
                  }
                }
                """;
        TerraformConfigSourceManifest manifest = TerraformConfigSourceExtractor.extract(
                List.of(new TerraformConfigIdentity.NamedConfigFile("main.tf.json", json.getBytes(StandardCharsets.UTF_8))));
        assertEquals(List.of("registry.terraform.io/some/module"), manifest.moduleSources());
    }

    @Test
    void disallowedCustomProviderRegistryHostBlocksBeforeInitEverRuns(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-custom-registry", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace,
                singleFile("""
                        terraform {
                          required_providers {
                            aws = {
                              source = "example.com/evil/aws"
                            }
                          }
                        }
                        """.getBytes(StandardCharsets.UTF_8)));

        assertEquals(List.of(RunnerReasonCode.TERRAFORM_PROVIDER_SOURCE_UNTRUSTED), evidence.reasonCodes());
        assertFalse(Files.exists(marker));
    }

    // ===================== security amendment: explicit provider declaration required =====================

    @Test
    void resourceUsingAProviderAbsentFromRequiredProvidersBlocksBeforeInitEverRuns(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        // No `terraform { required_providers { tls = {...} } }` declaration at all - Terraform would
        // resolve the "tls" provider implicitly (registry.terraform.io/hashicorp/tls) with nothing
        // for TerraformSourcePolicy to have ever evaluated.
        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-implicit-resource", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace,
                singleFile("resource \"tls_private_key\" \"key\" {\n  algorithm = \"RSA\"\n}\n".getBytes(StandardCharsets.UTF_8)));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_PROVIDER_REQUIREMENT_IMPLICIT), evidence.reasonCodes());
        assertFalse(Files.exists(marker), "init must never launch for a provider dependency with no explicit required_providers entry");
    }

    @Test
    void providerBlockAbsentFromRequiredProvidersBlocksBeforeInitEverRuns(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-implicit-provider-block", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace,
                singleFile("provider \"tls\" {\n  alias = \"secondary\"\n}\n".getBytes(StandardCharsets.UTF_8)));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_PROVIDER_REQUIREMENT_IMPLICIT), evidence.reasonCodes());
        assertFalse(Files.exists(marker));
    }

    @Test
    void explicitlyRequiredProviderWithAnAllowedCanonicalSourceIsAllowed(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "echo 'lock' > .terraform.lock.hcl\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-explicit-allowed", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace,
                singleFile("""
                        terraform {
                          required_providers {
                            tls = {
                              source = "registry.terraform.io/hashicorp/tls"
                            }
                          }
                        }
                        resource "tls_private_key" "key" {
                          algorithm = "RSA"
                        }
                        """.getBytes(StandardCharsets.UTF_8)));

        assertEquals(TerraformProcessState.SUCCEEDED, evidence.processState(), evidence.reasonCodes().toString());
    }

    @Test
    void explicitlyRequiredProviderWithADisallowedSourceIsBlocked(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-explicit-disallowed", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace,
                singleFile("""
                        terraform {
                          required_providers {
                            tls = {
                              source = "example.com/evil/tls"
                            }
                          }
                        }
                        resource "tls_private_key" "key" {
                          algorithm = "RSA"
                        }
                        """.getBytes(StandardCharsets.UTF_8)));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_PROVIDER_SOURCE_UNTRUSTED), evidence.reasonCodes());
        assertFalse(Files.exists(marker));
    }

    @Test
    void builtinTerraformProviderResourceIsExemptFromTheExplicitDeclarationRequirement(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED, "exit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-builtin-provider", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(TerraformProcessState.SUCCEEDED, evidence.processState(), evidence.reasonCodes().toString());
    }

    // ===================== security amendment: effective provider-name resolution =====================

    @Test
    void resourceWithoutExplicitProviderAndAMatchingRequiredProviderIsAllowed(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "echo 'lock' > .terraform.lock.hcl\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-implicit-ok", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace,
                singleFile("""
                        terraform {
                          required_providers {
                            aws = {
                              source = "registry.terraform.io/hashicorp/aws"
                            }
                          }
                        }
                        resource "aws_s3_bucket" "example" {}
                        """.getBytes(StandardCharsets.UTF_8)));

        assertEquals(TerraformProcessState.SUCCEEDED, evidence.processState(), evidence.reasonCodes().toString());
    }

    @Test
    void resourceWithoutExplicitProviderAndAMissingRequiredProviderBlocksBeforeInit(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-implicit-missing", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace,
                singleFile("resource \"aws_s3_bucket\" \"example\" {}\n".getBytes(StandardCharsets.UTF_8)));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_PROVIDER_REQUIREMENT_IMPLICIT), evidence.reasonCodes());
        assertFalse(Files.exists(marker));
    }

    @Test
    void resourceWithExplicitProviderLocalNameAndAMatchingRequiredProviderIsAllowed(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "echo 'lock' > .terraform.lock.hcl\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-explicit-provider-plain", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace,
                singleFile("""
                        terraform {
                          required_providers {
                            corpaws = {
                              source = "registry.terraform.io/hashicorp/aws"
                            }
                          }
                        }
                        resource "aws_s3_bucket" "example" {
                          provider = corpaws
                        }
                        """.getBytes(StandardCharsets.UTF_8)));

        assertEquals(TerraformProcessState.SUCCEEDED, evidence.processState(), evidence.reasonCodes().toString());
    }

    @Test
    void resourceWithExplicitProviderAliasAndAMatchingRequiredProviderIsAllowed(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "echo 'lock' > .terraform.lock.hcl\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-explicit-provider-alias", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace,
                singleFile("""
                        terraform {
                          required_providers {
                            corpaws = {
                              source = "registry.terraform.io/hashicorp/aws"
                            }
                          }
                        }
                        resource "aws_s3_bucket" "example" {
                          provider = corpaws.east
                        }
                        """.getBytes(StandardCharsets.UTF_8)));

        assertEquals(TerraformProcessState.SUCCEEDED, evidence.processState(), evidence.reasonCodes().toString());
    }

    @Test
    void resourceTypePrefixIsNotAlsoRequiredWhenAnExplicitProviderOverridesIt(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        // "aws_s3_bucket" would imply local name "aws" by type prefix alone, but the explicit
        // `provider = corpaws.east` override means "aws" must NOT also be required - only "corpaws".
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "echo 'lock' > .terraform.lock.hcl\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-explicit-overrides-prefix", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace,
                singleFile("""
                        terraform {
                          required_providers {
                            corpaws = {
                              source = "registry.terraform.io/hashicorp/aws"
                            }
                          }
                        }
                        resource "aws_s3_bucket" "example" {
                          provider = corpaws.east
                        }
                        """.getBytes(StandardCharsets.UTF_8)));

        // No required_providers.aws entry exists anywhere in this configuration - if the type prefix
        // were falsely also required, this would incorrectly block with TERRAFORM_PROVIDER_REQUIREMENT_IMPLICIT.
        assertEquals(TerraformProcessState.SUCCEEDED, evidence.processState(), evidence.reasonCodes().toString());
    }

    @Test
    void explicitProviderReferenceToAnUndeclaredLocalNameBlocksBeforeInit(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-explicit-undeclared", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace,
                singleFile("""
                        terraform {
                          required_providers {
                            aws = {
                              source = "registry.terraform.io/hashicorp/aws"
                            }
                          }
                        }
                        resource "aws_s3_bucket" "example" {
                          provider = unexpected.foo
                        }
                        """.getBytes(StandardCharsets.UTF_8)));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_PROVIDER_REQUIREMENT_IMPLICIT), evidence.reasonCodes());
        assertFalse(Files.exists(marker));
    }

    @Test
    void malformedOrDynamicProviderReferenceFailsExtractionClosedBeforeInit(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-dynamic-provider", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace,
                singleFile("""
                        terraform {
                          required_providers {
                            aws = {
                              source = "registry.terraform.io/hashicorp/aws"
                            }
                          }
                        }
                        resource "aws_s3_bucket" "example" {
                          provider = local.provider_map[var.env]
                        }
                        """.getBytes(StandardCharsets.UTF_8)));

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_SOURCE_EXTRACTION_FAILED), evidence.reasonCodes());
        assertFalse(Files.exists(marker));
    }

    @Test
    void jsonResourceWithExplicitProviderAliasIsHandledEquivalently() {
        String json = """
                {
                  "terraform": {
                    "required_providers": {
                      "corpaws": { "source": "registry.terraform.io/hashicorp/aws" }
                    }
                  },
                  "resource": {
                    "aws_s3_bucket": {
                      "example": { "provider": "corpaws.east" }
                    }
                  }
                }
                """;
        TerraformConfigSourceManifest manifest = TerraformConfigSourceExtractor.extract(
                List.of(new TerraformConfigIdentity.NamedConfigFile("main.tf.json", json.getBytes(StandardCharsets.UTF_8))));
        assertTrue(manifest.declaredProviderLocalNames().contains("corpaws"));
        assertTrue(manifest.impliedProviderLocalNames().contains("corpaws"));
        assertFalse(manifest.impliedProviderLocalNames().contains("aws"), "the type prefix must not also be implied when an explicit provider overrides it");
    }

    @Test
    void jsonResourceWithoutExplicitProviderAndUndeclaredRequiredProviderIsFlaggedAsImplied() {
        String json = """
                {
                  "resource": {
                    "tls_private_key": {
                      "key": { "algorithm": "RSA" }
                    }
                  }
                }
                """;
        TerraformConfigSourceManifest manifest = TerraformConfigSourceExtractor.extract(
                List.of(new TerraformConfigIdentity.NamedConfigFile("main.tf.json", json.getBytes(StandardCharsets.UTF_8))));
        assertTrue(manifest.undeclaredImpliedProviderLocalNames().contains("tls"));
    }

    @Test
    void jsonImportBlockWithExplicitProviderIsIncludedInTheImpliedSet() {
        String json = """
                {
                  "import": [
                    { "to": "aws_instance.example", "id": "i-abc", "provider": "corpaws.east" }
                  ]
                }
                """;
        TerraformConfigSourceManifest manifest = TerraformConfigSourceExtractor.extract(
                List.of(new TerraformConfigIdentity.NamedConfigFile("main.tf.json", json.getBytes(StandardCharsets.UTF_8))));
        assertTrue(manifest.impliedProviderLocalNames().contains("corpaws"));
    }

    @Test
    void nativeImportBlockWithExplicitProviderIsIncludedInTheImpliedSet() {
        String config = """
                import {
                  to = aws_instance.example
                  id = "i-abc"
                  provider = corpaws.east
                }
                """;
        TerraformConfigSourceManifest manifest = TerraformConfigSourceExtractor.extract(singleFile(config.getBytes(StandardCharsets.UTF_8)));
        assertTrue(manifest.impliedProviderLocalNames().contains("corpaws"));
    }

    @Test
    void disallowedHttpModuleSourceBlocksBeforeInitEverRuns(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-http-module", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace,
                singleFile("module \"foo\" {\n  source = \"https://example.com/evil/module.zip\"\n}\n".getBytes(StandardCharsets.UTF_8)));

        assertEquals(List.of(RunnerReasonCode.TERRAFORM_MODULE_DEPENDENCY_GRAPH_UNRESOLVED), evidence.reasonCodes());
        assertFalse(Files.exists(marker));
    }

    @Test
    void registryModuleSourceStillBlocksInitEvenWhenSourcePolicyWouldAllowIt(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        TerraformSourcePolicy policy = new TerraformSourcePolicy(Set.of(), Set.of("registry.terraform.io/some/"), true, false, false);
        assertTrue(policy.isModuleSourceAllowed("registry.terraform.io/some/module"), "test setup: this policy must actually permit the module source");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, policy, TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-registry-module", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace,
                singleFile("module \"foo\" {\n  source = \"registry.terraform.io/some/module\"\n}\n".getBytes(StandardCharsets.UTF_8)));

        // Even a directly policy-allowed registry module cannot execute in this phase - a module's
        // own downloaded contents can introduce further, unvetted provider/module dependencies that
        // this runner does not yet recursively stage/parse/validate.
        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_MODULE_DEPENDENCY_GRAPH_UNRESOLVED), evidence.reasonCodes());
        assertFalse(Files.exists(marker), "init must never launch for a module block, even a policy-allowed one");
    }

    @Test
    void interpolatedSourceValueFailsExtractionClosedBeforeInitEverRuns(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path marker = trustedRoot.resolve("INIT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "touch '" + marker + "'\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidence = coordinator.executeInit(
                baseRequest("r-interpolated-source", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace,
                singleFile("module \"foo\" {\n  source = \"${var.registry}/hashicorp/aws\"\n}\n".getBytes(StandardCharsets.UTF_8)));

        assertEquals(List.of(RunnerReasonCode.TERRAFORM_SOURCE_EXTRACTION_FAILED), evidence.reasonCodes());
        assertFalse(Files.exists(marker), "init must never have actually run when a source could not be deterministically extracted");
    }

    @Test
    void malformedNativeConfigurationFailsExtractionClosed() {
        String malformed = "terraform {\n  required_providers {\n    aws = {\n      source = \"registry.terraform.io/hashicorp/aws\"\n"; // missing closing braces
        assertThrows(TerraformConfigSourceExtractionException.class,
                () -> TerraformConfigSourceExtractor.extract(singleFile(malformed.getBytes(StandardCharsets.UTF_8))));
    }

    @Test
    void malformedTfJsonFailsExtractionClosed() {
        String malformed = "{ \"terraform\": { \"required_providers\": "; // truncated JSON
        assertThrows(TerraformConfigSourceExtractionException.class,
                () -> TerraformConfigSourceExtractor.extract(List.of(new TerraformConfigIdentity.NamedConfigFile("main.tf.json", malformed.getBytes(StandardCharsets.UTF_8)))));
    }

    @Test
    void unrecognizedFileExtensionFailsExtractionClosed() {
        assertThrows(TerraformConfigSourceExtractionException.class, () -> TerraformConfigSourceExtractor.extract(
                List.of(new TerraformConfigIdentity.NamedConfigFile("main.tfvars", "irrelevant".getBytes(StandardCharsets.UTF_8)))));
    }

    @Test
    void overrideFileSourceDeclarationSupersedesTheRegularFileForTheSameModule() {
        List<TerraformConfigIdentity.NamedConfigFile> files = List.of(
                new TerraformConfigIdentity.NamedConfigFile("main.tf",
                        "module \"foo\" {\n  source = \"registry.terraform.io/some/original\"\n}\n".getBytes(StandardCharsets.UTF_8)),
                new TerraformConfigIdentity.NamedConfigFile("override.tf",
                        "module \"foo\" {\n  source = \"registry.terraform.io/some/overridden\"\n}\n".getBytes(StandardCharsets.UTF_8)));
        TerraformConfigSourceManifest manifest = TerraformConfigSourceExtractor.extract(files);
        assertEquals(List.of("registry.terraform.io/some/overridden"), manifest.moduleSources());
    }

    // ===================== security amendment: filename-bound configuration identity =====================

    @Test
    void swappingContentBetweenMainAndOverrideProducesADifferentIdentity() {
        var mainX = new TerraformConfigIdentity.NamedConfigFile("main.tf", "X".getBytes(StandardCharsets.UTF_8));
        var overrideY = new TerraformConfigIdentity.NamedConfigFile("override.tf", "Y".getBytes(StandardCharsets.UTF_8));
        var mainY = new TerraformConfigIdentity.NamedConfigFile("main.tf", "Y".getBytes(StandardCharsets.UTF_8));
        var overrideX = new TerraformConfigIdentity.NamedConfigFile("override.tf", "X".getBytes(StandardCharsets.UTF_8));

        String identityA = TerraformConfigIdentity.computeSha256(List.of(mainX, overrideY));
        String identityB = TerraformConfigIdentity.computeSha256(List.of(mainY, overrideX));

        assertNotEquals(identityA, identityB, "swapping content between main.tf and override.tf must not collide - filenames are semantically significant");
    }

    @Test
    void sameRelativePathsAndContentProduceTheSameIdentityRegardlessOfWorkspaceRoot(@TempDir Path rootA, @TempDir Path rootB, @TempDir Path trustedRoot) throws IOException {
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED, "exit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinatorA = coordinatorFor(binary, trustedRoot, rootA, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);
        var coordinatorB = coordinatorFor(binary, trustedRoot, rootB, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence evidenceA = coordinatorA.executeInit(
                baseRequest("r-root-a", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), rootA, singleFile(PROVIDERLESS_CONFIG));
        TerraformInitEvidence evidenceB = coordinatorB.executeInit(
                baseRequest("r-root-b", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), rootB, singleFile(PROVIDERLESS_CONFIG));

        assertEquals(evidenceA.configSha256(), evidenceB.configSha256(),
                "identical relative paths/content staged under two different runner workspace roots must produce the same identity - no absolute path may leak into the hash");
    }

    @Test
    void sameContentUnderDotTfVersusDotTfJsonProducesDifferentIdentities() {
        byte[] content = "same-bytes".getBytes(StandardCharsets.UTF_8);
        String tfIdentity = TerraformConfigIdentity.computeSha256(List.of(new TerraformConfigIdentity.NamedConfigFile("foo.tf", content)));
        String tfJsonIdentity = TerraformConfigIdentity.computeSha256(List.of(new TerraformConfigIdentity.NamedConfigFile("foo.tf.json", content)));
        assertNotEquals(tfIdentity, tfJsonIdentity);
    }

    @Test
    void addingRemovingOrRenamingAFileChangesTheIdentity() {
        byte[] content = "same-bytes".getBytes(StandardCharsets.UTF_8);
        String oneFile = TerraformConfigIdentity.computeSha256(List.of(new TerraformConfigIdentity.NamedConfigFile("main.tf", content)));
        String twoFiles = TerraformConfigIdentity.computeSha256(List.of(
                new TerraformConfigIdentity.NamedConfigFile("main.tf", content),
                new TerraformConfigIdentity.NamedConfigFile("extra.tf", "more".getBytes(StandardCharsets.UTF_8))));
        String renamed = TerraformConfigIdentity.computeSha256(List.of(new TerraformConfigIdentity.NamedConfigFile("renamed.tf", content)));

        assertNotEquals(oneFile, twoFiles, "adding a file must change the identity");
        assertNotEquals(oneFile, renamed, "renaming a file must change the identity even with unchanged content");
    }

    @Test
    void lockfileContentChangeAffectsConfigurationIdentity() {
        byte[] configContent = "resource \"terraform_data\" \"x\" {}\n".getBytes(StandardCharsets.UTF_8);
        var configEntry = new TerraformConfigIdentity.NamedConfigFile("main.tf", configContent);
        String withoutLockfile = TerraformConfigIdentity.computeSha256(List.of(configEntry));
        String withLockfileA = TerraformConfigIdentity.computeSha256(
                List.of(configEntry, new TerraformConfigIdentity.NamedConfigFile(".terraform.lock.hcl", "lock-a".getBytes(StandardCharsets.UTF_8))));
        String withLockfileB = TerraformConfigIdentity.computeSha256(
                List.of(configEntry, new TerraformConfigIdentity.NamedConfigFile(".terraform.lock.hcl", "lock-b".getBytes(StandardCharsets.UTF_8))));

        assertNotEquals(withoutLockfile, withLockfileA);
        assertNotEquals(withLockfileA, withLockfileB);
    }

    @Test
    void initEvidenceConfigIdentityChangesWhenTheLockfileContentChanges(@TempDir Path workspace, @TempDir Path trustedRoot) throws IOException {
        Path binary = FakeExecutables.terraformInitStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED,
                "echo 'unchanged' > .terraform.lock.hcl\nexit 0\n", "exit 0\n", "echo '{}'\nexit 0\n");
        var coordinator = coordinatorFor(binary, trustedRoot, workspace, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);

        TerraformInitEvidence withoutLockfile = coordinator.executeInit(
                baseRequest("r-lock-identity-1", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        Files.writeString(workspace.resolve(".terraform.lock.hcl"), "unchanged\n");
        TerraformInitEvidence withLockfile = coordinator.executeInit(
                baseRequest("r-lock-identity-2", "a", "s", "ap", RunnerOperation.TERRAFORM_INIT), trustedIdentity(), workspace, singleFile(PROVIDERLESS_CONFIG));

        assertNotEquals(withoutLockfile.configSha256(), withLockfile.configSha256());
    }

    // ===================== helpers =====================

    private ControlledTerraformOperationCoordinator coordinatorFor(
            Path binary, Path trustedRoot, Path workspace, TerraformSourcePolicy sourcePolicy, TerraformBackendMode backendMode) throws IOException {
        var provider = new HostConfiguredTerraformExecutableProvider(binary, FakeExecutables.sha256Hex(binary), TERRAFORM_VERSION_EXPECTED, trustedRoot, List.of());
        return new ControlledTerraformOperationCoordinator(
                provider,
                new TerraformCommandFactory(new TerraformProcessEnvironmentPolicy(), new TerraformInitProcessEnvironmentPolicy()),
                new ControlledTerraformProcess(),
                new RunnerWorkspaceManager(workspace),
                Duration.ofSeconds(10), Duration.ofSeconds(10), Duration.ofSeconds(10),
                Duration.ofSeconds(10), Duration.ofSeconds(10), Duration.ofSeconds(10),
                sourcePolicy, backendMode);
    }

    private ControlledRunner runnerWithTerraform(Path root, InMemoryApprovalRepository repo, InMemoryRunnerArtifactStore artifactStore,
                                                  Path binary, Path trustedRoot) throws IOException {
        var provider = new HostConfiguredTerraformExecutableProvider(binary, FakeExecutables.sha256Hex(binary), TERRAFORM_VERSION_EXPECTED, trustedRoot, List.of(root));
        var coordinator = new ControlledTerraformOperationCoordinator(
                provider,
                new TerraformCommandFactory(new TerraformProcessEnvironmentPolicy(), new TerraformInitProcessEnvironmentPolicy()),
                new ControlledTerraformProcess(),
                new RunnerWorkspaceManager(root),
                Duration.ofSeconds(10), Duration.ofSeconds(10), Duration.ofSeconds(10),
                Duration.ofSeconds(10), Duration.ofSeconds(10), Duration.ofSeconds(10),
                TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);
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
