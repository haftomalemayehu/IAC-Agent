package com.iacagent.iacagent.runner;

import com.iacagent.iacagent.approval.ApprovalIssuanceRequest;
import com.iacagent.iacagent.approval.ApprovalProvenance;
import com.iacagent.iacagent.approval.ApprovalRecordProducer;
import com.iacagent.iacagent.approval.ApprovalTtlPolicy;
import com.iacagent.iacagent.approval.InMemoryApprovalRepository;
import com.iacagent.iacagent.approval.RepositoryBackedApprovalProvider;
import com.iacagent.iacagent.approval.TrustedApprovalContext;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
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
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 2B-3 tests: the controlled Terraform process boundary. Covers the executable trust model,
 * the closed command builder, {@link ControlledTerraformProcess} (environment clearing, stdin EOF,
 * output bounds, timeout/process-tree termination), the three allowed operations' interpretation
 * logic, the plan-hash TOCTOU recheck, and full {@link ControlledRunner} integration (same durable
 * claim/identity/approval pipeline every other operation goes through - no bypass).
 *
 * <p>Fake POSIX shell-script executables ({@link FakeExecutables}) stand in for Terraform in most
 * tests, per the phase's own guidance not to make ordinary test success depend on downloading
 * Terraform or on network access. A handful of tests additionally run against a real, locally
 * installed {@code terraform} binary when one is found at a fixed set of common install
 * locations - skipped (never failed) otherwise via {@link Assumptions#assumeTrue}.
 */
class Phase2b3Tests {

    private static final Instant NOW = Instant.parse("2026-09-11T00:00:00Z");
    private static final String REPOSITORY = "owner/repository";
    private static final String COMMIT_SHA = "c".repeat(40);
    private static final String ENVIRONMENT = "nonprod";
    private static final String TERRAFORM_VERSION_EXPECTED = "1.6.6";
    private static final String PROVIDER_LOCK_HASH = "sha256:lock-abc";
    private static final Set<String> ALLOWED_RUNNER_CLASSES = Set.of("terraform-test-runner");

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

    private RunnerIdentity trustedIdentity() {
        return new RunnerIdentity("runner-1", "terraform-test-runner", Set.of(ENVIRONMENT), true);
    }

    private String issueValidApproval(InMemoryApprovalRepository repo, String planSha) {
        ApprovalRecordProducer producer = new ApprovalRecordProducer(repo, new MutableClock(NOW), ApprovalTtlPolicy.fixed(Duration.ofHours(4)));
        ApprovalIssuanceRequest request = new ApprovalIssuanceRequest(REPOSITORY, COMMIT_SHA, ENVIRONMENT, planSha, ApprovalProvenance.NONE);
        return producer.issue(request, new TrustedApprovalContext("platform-admin"));
    }

    private RunnerRequest baseRequest(String requestId, String artifactId, String planSha256, String approvalId) {
        return new RunnerRequest(requestId, REPOSITORY, COMMIT_SHA, ENVIRONMENT, artifactId, planSha256,
                TERRAFORM_VERSION_EXPECTED, PROVIDER_LOCK_HASH, approvalId, RunnerOperation.TERRAFORM_VERSION);
    }

    private RunnerRequest withOperation(RunnerRequest base, RunnerOperation operation) {
        return new RunnerRequest(base.runnerRequestId(), base.repository(), base.commitSha(), base.environment(),
                base.planArtifactId(), base.planSha256(), base.terraformVersion(), base.providerLockHash(), base.approvalId(), operation);
    }

    // ===================== 28: command surface structural tests =====================

    @Test
    void onlyTheSixAllowedControlledTerraformOperationsExist() {
        Set<String> names = Arrays.stream(ControlledTerraformOperation.values()).map(Enum::name).collect(Collectors.toSet());
        // Phase 2B-4 added TERRAFORM_INIT/TERRAFORM_VALIDATE/TERRAFORM_PROVIDERS_SCHEMA under a
        // policy-governed trust boundary - see docs/phase-2b4-controlled-init-validation.md. PLAN
        // and APPLY remain deliberately absent.
        assertEquals(Set.of("TERRAFORM_VERSION", "TERRAFORM_FMT_CHECK", "TERRAFORM_SHOW_PLAN_JSON",
                "TERRAFORM_INIT", "TERRAFORM_VALIDATE", "TERRAFORM_PROVIDERS_SCHEMA"), names);
        for (String forbidden : List.of("PLAN", "APPLY", "DESTROY", "IMPORT",
                "STATE", "FORCE_UNLOCK", "TAINT", "UNTAINT", "REFRESH", "WORKSPACE", "GET")) {
            assertFalse(names.contains(forbidden), forbidden + " must not be representable");
        }
    }

    @Test
    void controlledTerraformProcessExecuteAcceptsOnlyAFullyTypedCommand() throws NoSuchMethodException {
        Method execute = ControlledTerraformProcess.class.getMethod("execute", ControlledTerraformCommand.class);
        assertEquals(1, execute.getParameterCount());
        assertEquals(ControlledTerraformCommand.class, execute.getParameterTypes()[0]);
        // no execute(String), execute(String...), runCommand(...), shell(...) exists at all
        for (Method m : ControlledTerraformProcess.class.getMethods()) {
            for (Class<?> paramType : m.getParameterTypes()) {
                assertNotEquals(String.class, paramType, m.getName() + " must not accept a raw String parameter");
                assertNotEquals(String[].class, paramType, m.getName() + " must not accept a String[] parameter");
            }
        }
    }

    @Test
    void terraformCommandFactoryHasNoMethodAcceptingArbitraryArgumentLists() {
        for (Method m : TerraformCommandFactory.class.getMethods()) {
            if (m.getDeclaringClass() != TerraformCommandFactory.class) {
                continue;
            }
            for (Class<?> paramType : m.getParameterTypes()) {
                assertNotEquals(List.class, paramType, m.getName() + " must not accept a caller-supplied List directly");
                assertNotEquals(String[].class, paramType, m.getName() + " must not accept a caller-supplied String[] directly");
            }
        }
    }

    // ===================== 29: executable trust tests =====================

    @Test
    void trustedBinaryUnderTrustedRootSucceeds(@TempDir Path trustedRoot, @TempDir Path untrustedRoot) throws IOException {
        Path binary = FakeExecutables.versionJson(trustedRoot, "terraform", "1.6.6", 0);
        String hash = FakeExecutables.sha256Hex(binary);
        var provider = new HostConfiguredTerraformExecutableProvider(binary, hash, "1.6.6", trustedRoot, List.of(untrustedRoot));

        TerraformExecutableResolution resolution = provider.resolve();

        assertEquals(TerraformExecutableResolutionOutcome.RESOLVED, resolution.outcome());
        assertEquals(hash, resolution.descriptor().expectedSha256());
    }

    @Test
    void requestCannotChooseTheExecutable(@TempDir Path trustedRoot, @TempDir Path untrustedRoot) throws IOException {
        Path binary = FakeExecutables.versionJson(trustedRoot, "terraform", "1.6.6", 0);
        var provider = new HostConfiguredTerraformExecutableProvider(binary, FakeExecutables.sha256Hex(binary), "1.6.6", trustedRoot, List.of(untrustedRoot));

        // resolve() takes zero parameters - structurally, no request could ever be passed to it.
        assertEquals(0, TerraformExecutableProvider.class.getDeclaredMethods()[0].getParameterCount());
        var first = provider.resolve();
        var second = provider.resolve();
        assertEquals(first.descriptor().executablePath(), second.descriptor().executablePath());
    }

    @Test
    void pathEnvironmentVariableDoesNotSelectTheBinary(@TempDir Path trustedRoot, @TempDir Path pathLookingDir) throws IOException {
        // A decoy "terraform" sitting somewhere that would be found via a hypothetical PATH lookup
        // must never be chosen - the provider only ever considers its own configured absolute path.
        FakeExecutables.versionJson(pathLookingDir, "terraform", "9.9.9-decoy", 0);
        Path realBinary = FakeExecutables.versionJson(trustedRoot, "terraform", "1.6.6", 0);
        var provider = new HostConfiguredTerraformExecutableProvider(
                realBinary, FakeExecutables.sha256Hex(realBinary), "1.6.6", trustedRoot, List.of(pathLookingDir));

        TerraformExecutableResolution resolution = provider.resolve();
        assertEquals(TerraformExecutableResolutionOutcome.RESOLVED, resolution.outcome());
        assertEquals(realBinary.toRealPath(), resolution.descriptor().executablePath());
    }

    @Test
    void constructorRejectsABinaryOutsideTheTrustedToolRoot(@TempDir Path trustedRoot, @TempDir Path elsewhere) throws IOException {
        Path binary = FakeExecutables.versionJson(elsewhere, "terraform", "1.6.6", 0);
        assertThrows(IllegalArgumentException.class,
                () -> new HostConfiguredTerraformExecutableProvider(binary, FakeExecutables.sha256Hex(binary), "1.6.6", trustedRoot, List.of()));
    }

    @Test
    void directSymlinkAtTheBinaryPathBlocks(@TempDir Path trustedRoot) throws IOException {
        Path realBinary = FakeExecutables.versionJson(trustedRoot, "real-terraform", "1.6.6", 0);
        Path symlinkBinary = trustedRoot.resolve("terraform");
        try {
            Files.createSymbolicLink(symlinkBinary, realBinary);
        } catch (UnsupportedOperationException | IOException e) {
            return;
        }
        var provider = new HostConfiguredTerraformExecutableProvider(
                symlinkBinary, FakeExecutables.sha256Hex(realBinary), "1.6.6", trustedRoot, List.of());

        assertEquals(TerraformExecutableResolutionOutcome.UNTRUSTED_PATH, provider.resolve().outcome());
    }

    @Test
    void ancestorSymlinkEscapeIntoAnUntrustedRootBlocks(@TempDir Path trustedRoot, @TempDir Path untrustedRoot) throws IOException {
        Path subdir = trustedRoot.resolve("bin");
        Path binaryPath = subdir.resolve("terraform"); // does not exist yet at construction time
        Path decoyTarget = untrustedRoot.resolve("attacker-bin");
        Files.createDirectory(decoyTarget);
        Path decoyBinary = FakeExecutables.versionJson(decoyTarget, "terraform", "1.6.6", 0);

        var provider = new HostConfiguredTerraformExecutableProvider(
                binaryPath, FakeExecutables.sha256Hex(decoyBinary), "1.6.6", trustedRoot, List.of(untrustedRoot));

        try {
            Files.createSymbolicLink(subdir, decoyTarget); // trustedRoot/bin now points into untrustedRoot
        } catch (UnsupportedOperationException | IOException e) {
            return;
        }

        assertEquals(TerraformExecutableResolutionOutcome.UNTRUSTED_PATH, provider.resolve().outcome());
    }

    @Test
    void binaryHashMismatchBlocksBeforeExecution(@TempDir Path trustedRoot, @TempDir Path untrustedRoot) throws IOException {
        Path binary = FakeExecutables.versionJson(trustedRoot, "terraform", "1.6.6", 0);
        var provider = new HostConfiguredTerraformExecutableProvider(binary, "sha256:not-the-real-hash", "1.6.6", trustedRoot, List.of(untrustedRoot));
        var coordinator = coordinatorFor(provider);

        RunnerRequest request = baseRequest("req-hash-mismatch", "artifact-1", "sha256:plan", "approval-1");
        Path workspace = Files.createTempDirectory("workspace");
        TerraformProcessEvidence evidence = coordinator.executeVersion(request, trustedIdentity(), workspace);

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_EXECUTABLE_HASH_MISMATCH), evidence.reasonCodes());
    }

    @Test
    void binaryReplacedAfterInitialValidationBlocksOnPerLaunchRecheck(@TempDir Path trustedRoot, @TempDir Path untrustedRoot) throws IOException {
        Path binary = FakeExecutables.versionJson(trustedRoot, "terraform", "1.6.6", 0);
        String originalHash = FakeExecutables.sha256Hex(binary);
        var provider = new HostConfiguredTerraformExecutableProvider(binary, originalHash, "1.6.6", trustedRoot, List.of(untrustedRoot));

        assertEquals(TerraformExecutableResolutionOutcome.RESOLVED, provider.resolve().outcome());

        // replace the binary's content in place - same path, different bytes
        FakeExecutables.versionJson(trustedRoot, "terraform", "9.9.9", 0);
        var coordinator = coordinatorFor(provider);
        RunnerRequest request = baseRequest("req-replaced", "artifact-1", "sha256:plan", "approval-1");
        TerraformProcessEvidence evidence = coordinator.executeVersion(request, trustedIdentity(), Files.createTempDirectory("workspace"));

        assertEquals(List.of(RunnerReasonCode.TERRAFORM_EXECUTABLE_HASH_MISMATCH), evidence.reasonCodes());
    }

    @Test
    void nonExecutableFileBlocks(@TempDir Path trustedRoot) throws IOException {
        Path notExecutable = trustedRoot.resolve("terraform");
        Files.writeString(notExecutable, "not actually executable");
        var provider = new HostConfiguredTerraformExecutableProvider(notExecutable, FakeExecutables.sha256Hex(notExecutable), "1.6.6", trustedRoot, List.of());

        assertEquals(TerraformExecutableResolutionOutcome.NOT_EXECUTABLE, provider.resolve().outcome());
    }

    @Test
    void missingBinaryBlocks(@TempDir Path trustedRoot) {
        Path missing = trustedRoot.resolve("terraform");
        var provider = new HostConfiguredTerraformExecutableProvider(missing, "sha256:whatever", "1.6.6", trustedRoot, List.of());

        assertEquals(TerraformExecutableResolutionOutcome.NOT_FOUND, provider.resolve().outcome());
    }

    // ===================== 30: environment tests =====================

    @Test
    void terraformProcessEnvironmentPolicyBuildsOnlyTheFixedExplicitEntrySet(@TempDir Path workspace) {
        TerraformProcessEnvironmentPolicy policy = new TerraformProcessEnvironmentPolicy();
        RunnerRequest request = baseRequest("req-env", "artifact-1", "sha256:plan", "approval-1");

        ProcessEnvironment env = policy.buildFor(request, workspace);

        assertEquals(Set.of("TF_IN_AUTOMATION", "TF_INPUT", "CHECKPOINT_DISABLE", "HOME", "TMPDIR"), env.variables().keySet());
        assertEquals("1", env.variables().get("CHECKPOINT_DISABLE"));
    }

    @Test
    void requestContentCannotInjectOrChangeTerraformEnvironmentVariables(@TempDir Path workspace) {
        TerraformProcessEnvironmentPolicy policy = new TerraformProcessEnvironmentPolicy();
        RunnerRequest benign = baseRequest("req-benign", "artifact-1", "sha256:plan", "approval-1");
        RunnerRequest hostile = new RunnerRequest("req-hostile", "PATH=/evil", "d".repeat(40), "AWS_ACCESS_KEY_ID=hijacked",
                "../../etc/passwd", "sha256:hostile", "0.0.0-evil", "sha256:hostile-lock", "approval-hostile", RunnerOperation.TERRAFORM_VERSION);

        assertEquals(policy.buildFor(benign, workspace), policy.buildFor(hostile, workspace));
    }

    @Test
    void environmentIsClearedBeforeLaunchAndHostAmbientVariablesDoNotPropagate(@TempDir Path dir, @TempDir Path workspace) throws IOException {
        Path script = FakeExecutables.envDump(dir, "probe", "PATH", "HOME", "USER", "AWS_ACCESS_KEY_ID", "GITHUB_TOKEN", "TF_IN_AUTOMATION", "CHECKPOINT_DISABLE");
        Files.setPosixFilePermissions(script, java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x"));
        // Sanity precondition: the JVM running this test really does have a non-empty PATH (true on
        // any real dev/CI machine) - otherwise this test would prove nothing about clearing.
        assertFalse(System.getenv("PATH") == null || System.getenv("PATH").isBlank(), "test precondition: host PATH must be non-empty");

        TerraformProcessEnvironmentPolicy policy = new TerraformProcessEnvironmentPolicy();
        RunnerRequest request = baseRequest("req-env-clear", "artifact-1", "sha256:plan", "approval-1");
        ControlledTerraformCommand command = new ControlledTerraformCommand(
                ControlledTerraformOperation.TERRAFORM_VERSION, List.of(script.toString()), workspace, policy.buildFor(request, workspace), Duration.ofSeconds(10));

        TerraformProcessResult result = new ControlledTerraformProcess().execute(command);
        String output = new String(result.stdout(), StandardCharsets.UTF_8);

        assertTrue(output.contains("PATH="), "probe must have run");
        // Note: some /bin/sh implementations (dash, in particular) fall back to a POSIX-mandated
        // default PATH (e.g. "/usr/bin:/bin") when they observe none at all in their own
        // environment - that is shell-internal behavior, not evidence that OUR code passed the
        // host's PATH through. The property this test actually verifies is that the HOST's real
        // PATH value (necessarily long/host-specific, e.g. containing this JVM's own toolchain
        // directories) never appears in the child - never that the child's shell reports a
        // completely blank PATH, which cannot be guaranteed portably.
        assertFalse(output.contains("PATH=" + System.getenv("PATH")), "host PATH must not propagate to the child");
        assertTrue(output.contains("AWS_ACCESS_KEY_ID=\n") || output.contains("AWS_ACCESS_KEY_ID=" + System.lineSeparator()));
        assertTrue(output.contains("GITHUB_TOKEN=\n") || output.contains("GITHUB_TOKEN=" + System.lineSeparator()));
        assertTrue(output.contains("TF_IN_AUTOMATION=true"));
        assertTrue(output.contains("CHECKPOINT_DISABLE=1"));
        assertTrue(output.contains("HOME=" + workspace.resolve("home")));
    }

    @Test
    void terraformEnvironmentHomeAndTmpdirRemainUnderTheWorkspace(@TempDir Path workspace) {
        TerraformProcessEnvironmentPolicy policy = new TerraformProcessEnvironmentPolicy();
        ProcessEnvironment env = policy.buildFor(baseRequest("req-env", "artifact-1", "sha256:plan", "approval-1"), workspace);

        assertTrue(Path.of(env.variables().get("HOME")).startsWith(workspace));
        assertTrue(Path.of(env.variables().get("TMPDIR")).startsWith(workspace));
    }

    // ===================== 31: stdin =====================

    @Test
    void stdinIsClosedRatherThanInherited(@TempDir Path dir, @TempDir Path workspace) throws IOException {
        Path script = FakeExecutables.stdinProbe(dir, "probe");
        ControlledTerraformCommand command = new ControlledTerraformCommand(
                ControlledTerraformOperation.TERRAFORM_VERSION, List.of(script.toString()), workspace,
                new TerraformProcessEnvironmentPolicy().buildFor(baseRequest("req-stdin", "a", "sha256:plan", "approval-1"), workspace),
                Duration.ofSeconds(10));

        TerraformProcessResult result = new ControlledTerraformProcess().execute(command);

        assertTrue(new String(result.stdout(), StandardCharsets.UTF_8).contains("STDIN_EOF"),
                "the child must observe immediate EOF on stdin, never inherited input");
    }

    // ===================== 32: timeout / kill =====================

    @Test
    void timeoutTerminatesTheProcessDeterministically(@TempDir Path dir, @TempDir Path workspace) throws IOException {
        Path script = FakeExecutables.busyWait(dir, "spin", 5_000_000_000L);
        ControlledTerraformCommand command = new ControlledTerraformCommand(
                ControlledTerraformOperation.TERRAFORM_FMT_CHECK, List.of(script.toString()), workspace,
                new TerraformProcessEnvironmentPolicy().buildFor(baseRequest("req-timeout", "a", "sha256:plan", "approval-1"), workspace),
                Duration.ofMillis(300));

        TerraformProcessResult result = new ControlledTerraformProcess().execute(command);

        assertTrue(result.timedOut());
        assertFalse(result.outputLimitExceeded());
        assertFalse(result.startFailed());
    }

    @Test
    void descendantProcessIsBestEffortTerminatedOnTimeout(@TempDir Path dir, @TempDir Path workspace) throws IOException, InterruptedException {
        Path counterFile = dir.resolve("child-counter.txt");
        String script = "#!/bin/sh\n"
                + "( i=0; while [ $i -lt 100000000 ]; do i=$((i+1)); echo $i > '" + counterFile + "'; done ) &\n"
                + "i=0\n"
                + "while [ $i -lt 100000000 ]; do i=$((i+1)); done\n"
                + "exit 0\n";
        Path parentScript = FakeExecutables.write(dir, "parent-with-child", script);

        ControlledTerraformCommand command = new ControlledTerraformCommand(
                ControlledTerraformOperation.TERRAFORM_FMT_CHECK, List.of(parentScript.toString()), workspace,
                new TerraformProcessEnvironmentPolicy().buildFor(baseRequest("req-descendant", "a", "sha256:plan", "approval-1"), workspace),
                Duration.ofMillis(300));

        TerraformProcessResult result = new ControlledTerraformProcess().execute(command);
        assertTrue(result.timedOut());

        Optional<Long> valueAfterKill = readCounterQuietly(counterFile);
        if (valueAfterKill.isEmpty()) {
            return; // the background child never got far enough to write a readable value yet -
                     // platform/timing dependent (including a read racing an in-progress truncate+
                     // rewrite), not evidence of anything - not a failure.
        }
        Thread.sleep(400); // grace period past the parent's own timeout/kill
        Optional<Long> valueLater = readCounterQuietly(counterFile);
        assertTrue(valueLater.isPresent(), "counter file became unreadable after being readable once - unexpected, but not itself evidence of a leaked process");
        assertEquals(valueAfterKill.get(), valueLater.get(), "the background child must have been terminated too, not left running after the parent was killed");
    }

    /** Reads the counter file, tolerating a read racing the child's own truncate+rewrite (which can
     * observe empty or partial content) by returning empty rather than failing the test outright. */
    private static Optional<Long> readCounterQuietly(Path counterFile) {
        try {
            String text = Files.readString(counterFile).trim();
            return text.isEmpty() ? Optional.empty() : Optional.of(Long.parseLong(text));
        } catch (IOException | NumberFormatException e) {
            return Optional.empty();
        }
    }

    // ===================== 33: output bounds =====================

    @Test
    void stdoutOutputLimitTerminatesTheProcessAndIsRecorded(@TempDir Path dir, @TempDir Path workspace) throws IOException {
        Path script = FakeExecutables.largeOutput(dir, "loud-stdout", "0123456789", 100_000, false);
        ControlledTerraformCommand command = new ControlledTerraformCommand(
                ControlledTerraformOperation.TERRAFORM_FMT_CHECK, List.of(script.toString()), workspace,
                new TerraformProcessEnvironmentPolicy().buildFor(baseRequest("req-stdout-limit", "a", "sha256:plan", "approval-1"), workspace),
                Duration.ofSeconds(20));

        TerraformProcessResult result = new ControlledTerraformProcess(200, ControlledTerraformProcess.DEFAULT_STDERR_MAX_BYTES).execute(command);

        assertTrue(result.outputLimitExceeded());
        assertFalse(result.timedOut());
        assertTrue(result.stdout().length <= 200, "captured stdout must never exceed the configured bound");
    }

    @Test
    void stderrOutputLimitTerminatesTheProcessIndependentlyOfStdout(@TempDir Path dir, @TempDir Path workspace) throws IOException {
        Path script = FakeExecutables.largeOutput(dir, "loud-stderr", "0123456789", 100_000, true);
        ControlledTerraformCommand command = new ControlledTerraformCommand(
                ControlledTerraformOperation.TERRAFORM_FMT_CHECK, List.of(script.toString()), workspace,
                new TerraformProcessEnvironmentPolicy().buildFor(baseRequest("req-stderr-limit", "a", "sha256:plan", "approval-1"), workspace),
                Duration.ofSeconds(20));

        TerraformProcessResult result = new ControlledTerraformProcess(ControlledTerraformProcess.DEFAULT_STDOUT_MAX_BYTES, 200).execute(command);

        assertTrue(result.outputLimitExceeded());
    }

    @Test
    void outputLimitExceededNeverBecomesSucceededEvenIfExitCodeWouldHaveBeenZero(@TempDir Path trustedRoot, @TempDir Path dir) throws IOException {
        Path script = FakeExecutables.write(dir, "terraform", "#!/bin/sh\n"
                + "i=0\nwhile [ $i -lt 100000 ]; do echo '0123456789'; i=$((i+1)); done\nexit 0\n");
        // relocate under trustedRoot so it passes executable trust
        Path binary = trustedRoot.resolve("terraform");
        Files.move(script, binary);
        Files.setPosixFilePermissions(binary, java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x"));
        var provider = new HostConfiguredTerraformExecutableProvider(binary, FakeExecutables.sha256Hex(binary), "1.6.6", trustedRoot, List.of());
        var process = new ControlledTerraformProcess(100, ControlledTerraformProcess.DEFAULT_STDERR_MAX_BYTES);
        var coordinator = new ControlledTerraformOperationCoordinator(
                provider, new TerraformCommandFactory(new TerraformProcessEnvironmentPolicy()), process,
                Duration.ofSeconds(10), Duration.ofSeconds(10), Duration.ofSeconds(10));

        TerraformProcessEvidence evidence = coordinator.executeVersion(
                baseRequest("req-overflow", "a", "sha256:plan", "approval-1"), trustedIdentity(), Files.createTempDirectory("workspace"));

        assertEquals(TerraformProcessState.OUTPUT_LIMIT_EXCEEDED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_OUTPUT_LIMIT_EXCEEDED), evidence.reasonCodes());
    }

    // ===================== 34: Terraform version (fake + optional real) =====================

    @Test
    void expectedVersionSucceeds(@TempDir Path trustedRoot) throws IOException {
        var coordinator = fakeVersionCoordinator(trustedRoot, "1.6.6", 0, "1.6.6");
        TerraformProcessEvidence evidence = coordinator.executeVersion(
                baseRequest("req-v-ok", "a", "sha256:plan", "approval-1"), trustedIdentity(), Files.createTempDirectory("workspace"));

        assertEquals(TerraformProcessState.SUCCEEDED, evidence.processState());
        assertEquals("1.6.6", evidence.terraformVersionObserved());
        assertTrue(evidence.reasonCodes().isEmpty());
    }

    @Test
    void unexpectedVersionBlocks(@TempDir Path trustedRoot) throws IOException {
        var coordinator = fakeVersionCoordinator(trustedRoot, "1.9.9", 0, "1.6.6");
        TerraformProcessEvidence evidence = coordinator.executeVersion(
                baseRequest("req-v-mismatch", "a", "sha256:plan", "approval-1"), trustedIdentity(), Files.createTempDirectory("workspace"));

        assertEquals(TerraformProcessState.FAILED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_VERSION_MISMATCH), evidence.reasonCodes());
        assertEquals("1.9.9", evidence.terraformVersionObserved());
    }

    @Test
    void invalidVersionJsonBlocks(@TempDir Path trustedRoot) throws IOException {
        Path binary = FakeExecutables.malformedJson(trustedRoot, "terraform");
        var coordinator = coordinatorForBinary(binary, "1.6.6", trustedRoot);
        TerraformProcessEvidence evidence = coordinator.executeVersion(
                baseRequest("req-v-invalid", "a", "sha256:plan", "approval-1"), trustedIdentity(), Files.createTempDirectory("workspace"));

        assertEquals(TerraformProcessState.FAILED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_VERSION_OUTPUT_INVALID), evidence.reasonCodes());
    }

    @Test
    void realTerraformBinaryVersionDetectionAndMismatch(@TempDir Path trustedRoot) throws IOException {
        Path realTerraform = findRealTerraform();
        Assumptions.assumeTrue(realTerraform != null, "no local terraform binary found - skipping real-binary integration test");
        Path binary = trustedRoot.resolve("terraform");
        Files.copy(realTerraform, binary);
        Files.setPosixFilePermissions(binary, java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x"));
        String hash = FakeExecutables.sha256Hex(binary);

        // The locally installed binary's actual version is whatever it is - success requires
        // matching THAT exact version, proving real end-to-end version parsing against genuine
        // `terraform version -json` output, not just our own fake fixture's shape.
        String actualVersion = detectRealTerraformVersion(binary);
        Assumptions.assumeTrue(actualVersion != null, "could not determine local terraform's version - skipping");

        var matching = new ControlledTerraformOperationCoordinator(
                new HostConfiguredTerraformExecutableProvider(binary, hash, actualVersion, trustedRoot, List.of()),
                new TerraformCommandFactory(new TerraformProcessEnvironmentPolicy()), new ControlledTerraformProcess(),
                Duration.ofSeconds(30), Duration.ofSeconds(30), Duration.ofSeconds(30));
        TerraformProcessEvidence success = matching.executeVersion(
                baseRequest("req-real-v-ok", "a", "sha256:plan", "approval-1"), trustedIdentity(), Files.createTempDirectory("workspace"));
        assertEquals(TerraformProcessState.SUCCEEDED, success.processState());

        var mismatched = new ControlledTerraformOperationCoordinator(
                new HostConfiguredTerraformExecutableProvider(binary, hash, "1.6.6-definitely-not-installed", trustedRoot, List.of()),
                new TerraformCommandFactory(new TerraformProcessEnvironmentPolicy()), new ControlledTerraformProcess(),
                Duration.ofSeconds(30), Duration.ofSeconds(30), Duration.ofSeconds(30));
        TerraformProcessEvidence mismatch = mismatched.executeVersion(
                baseRequest("req-real-v-mismatch", "a", "sha256:plan", "approval-1"), trustedIdentity(), Files.createTempDirectory("workspace"));
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_VERSION_MISMATCH), mismatch.reasonCodes());
    }

    // ===================== version binding for FMT_CHECK / SHOW_PLAN_JSON (amendment) =====================
    // A trusted SHA-256 alone must not be sufficient for these two operations: a hash-trusted
    // binary that reports the wrong Terraform version must still block, and must never reach its
    // own requested command (fmt/show) - proven here via a marker file the fixture would create
    // only if that command actually ran.

    @Test
    void wrongReportedVersionBlocksFmtCheckBeforeItEverRuns(@TempDir Path trustedRoot, @TempDir Path workspace) throws IOException {
        Path marker = trustedRoot.resolve("FMT_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformStub(trustedRoot, "terraform", "9.9.9-wrong", 0, "touch '" + marker + "'\nexit 0\n");
        var coordinator = coordinatorForBinary(binary, TERRAFORM_VERSION_EXPECTED, trustedRoot);

        TerraformProcessEvidence evidence = coordinator.executeFmtCheck(
                baseRequest("req-fmt-version-mismatch", "a", "sha256:plan", "approval-1"), trustedIdentity(), workspace);

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_VERSION_MISMATCH), evidence.reasonCodes());
        assertEquals("9.9.9-wrong", evidence.terraformVersionObserved(), "the observed (wrong) version must still be recorded in evidence");
        assertFalse(Files.exists(marker), "fmt -check must never have actually run once version verification failed");
    }

    @Test
    void wrongReportedVersionBlocksShowPlanJsonBeforeItEverRuns(@TempDir Path trustedRoot, @TempDir Path workspace) throws IOException {
        byte[] plan = "plan-bytes".getBytes(StandardCharsets.UTF_8);
        String hash = sha256Hex(plan);
        Path stagedPlan = workspace.resolve("sha256-" + hash + ".tfplan");
        Files.write(stagedPlan, plan);
        Path marker = trustedRoot.resolve("SHOW_EXECUTED_MARKER");
        Path binary = FakeExecutables.terraformStub(trustedRoot, "terraform", "9.9.9-wrong", 0, "touch '" + marker + "'\necho '{}'\nexit 0\n");
        var coordinator = coordinatorForBinary(binary, TERRAFORM_VERSION_EXPECTED, trustedRoot);

        TerraformProcessEvidence evidence = coordinator.executeShowPlanJson(
                baseRequest("req-show-version-mismatch", "a", hash, "approval-1"), trustedIdentity(), workspace, stagedPlan, hash);

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_VERSION_MISMATCH), evidence.reasonCodes());
        assertEquals("9.9.9-wrong", evidence.terraformVersionObserved());
        assertFalse(Files.exists(marker), "show -json must never have actually run once version verification failed");
    }

    @Test
    void fmtCheckEvidenceCarriesTheObservedVersionOnSuccess(@TempDir Path trustedRoot, @TempDir Path workspace) throws IOException {
        Path binary = FakeExecutables.terraformStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED, 0, "exit 0\n");
        var coordinator = coordinatorForBinary(binary, TERRAFORM_VERSION_EXPECTED, trustedRoot);

        TerraformProcessEvidence evidence = coordinator.executeFmtCheck(baseRequest("req-fmt-version-ok", "a", "sha256:plan", "approval-1"), trustedIdentity(), workspace);

        assertEquals(TerraformProcessState.SUCCEEDED, evidence.processState());
        assertEquals(TERRAFORM_VERSION_EXPECTED, evidence.terraformVersionObserved(), "FMT_CHECK evidence must carry the bound observed version, not null");
    }

    @Test
    void showPlanJsonEvidenceCarriesTheObservedVersionOnSuccess(@TempDir Path trustedRoot, @TempDir Path workspace) throws IOException {
        byte[] plan = "plan-bytes".getBytes(StandardCharsets.UTF_8);
        String hash = sha256Hex(plan);
        Path stagedPlan = workspace.resolve("sha256-" + hash + ".tfplan");
        Files.write(stagedPlan, plan);
        Path binary = FakeExecutables.terraformStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED, 0, "echo '{}'\nexit 0\n");
        var coordinator = coordinatorForBinary(binary, TERRAFORM_VERSION_EXPECTED, trustedRoot);

        TerraformProcessEvidence evidence = coordinator.executeShowPlanJson(
                baseRequest("req-show-version-ok", "a", hash, "approval-1"), trustedIdentity(), workspace, stagedPlan, hash);

        assertEquals(TerraformProcessState.SUCCEEDED, evidence.processState());
        assertEquals(TERRAFORM_VERSION_EXPECTED, evidence.terraformVersionObserved(), "SHOW_PLAN_JSON evidence must carry the bound observed version, not null");
    }

    @Test
    void versionAttestationIsReusedAcrossCallsForAnUnchangedBinaryButNotAcrossAReplacedOne(@TempDir Path trustedRoot, @TempDir Path workspace) throws IOException {
        Path counterFile = trustedRoot.resolve("version_call_count.txt");
        Files.writeString(counterFile, "0");
        // Every invocation (version or otherwise) bumps the counter using only shell builtins, so
        // we can distinguish "the version subcommand ran" from "it was skipped via the cache."
        String bumpAndCheck = "n=$(cat '" + counterFile + "'); n=$((n+1)); echo $n > '" + counterFile + "'\n"
                + "if [ \"$1\" = \"version\" ]; then echo '{\"terraform_version\":\"" + TERRAFORM_VERSION_EXPECTED + "\"}'; exit 0; fi\n"
                + "exit 0\n";
        Path binary = FakeExecutables.write(trustedRoot, "terraform", "#!/bin/sh\n" + bumpAndCheck);
        Files.setPosixFilePermissions(binary, java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x"));
        var coordinator = coordinatorForBinary(binary, TERRAFORM_VERSION_EXPECTED, trustedRoot);

        coordinator.executeFmtCheck(baseRequest("req-cache-1", "a", "sha256:plan", "approval-1"), trustedIdentity(), workspace);
        long afterFirst = Long.parseLong(Files.readString(counterFile).trim());
        coordinator.executeFmtCheck(baseRequest("req-cache-2", "a", "sha256:plan", "approval-1"), trustedIdentity(), workspace);
        long afterSecond = Long.parseLong(Files.readString(counterFile).trim());

        // First call: one invocation to establish the attestation (version), one for the actual fmt
        // command = +2. Second call, same unchanged binary: attestation is reused from cache, only
        // the fmt command itself runs = +1, not +2.
        assertEquals(2, afterFirst);
        assertEquals(3, afterSecond, "a second call against the SAME unchanged binary must not re-run the version check");
    }

    // ===================== 35: saved plan (SHOW_PLAN_JSON) =====================

    @Test
    void showPlanJsonUsesOnlyTheStagedPlanPath(@TempDir Path trustedRoot, @TempDir Path workspace) throws IOException {
        Path binary = FakeExecutables.versionJson(trustedRoot, "terraform", "1.6.6", 0);
        Path stagedPlan = workspace.resolve("sha256-abc.tfplan");
        Files.writeString(stagedPlan, "fake plan bytes");
        TerraformCommandFactory factory = new TerraformCommandFactory(new TerraformProcessEnvironmentPolicy());
        var descriptor = new TerraformExecutableDescriptor(binary.toRealPath(), FakeExecutables.sha256Hex(binary), "1.6.6", trustedRoot.toRealPath());

        ControlledTerraformCommand command = factory.showPlanJsonCommand(
                baseRequest("req-plan", "a", "sha256:plan", "approval-1"), descriptor, workspace, stagedPlan, Duration.ofSeconds(10));

        assertEquals(List.of(binary.toRealPath().toString(), "show", "-json", stagedPlan.toString()), command.argv());
    }

    @Test
    void requestCannotOverrideTheStagedPlanPath() throws NoSuchMethodException {
        // showPlanJsonCommand's only path-shaped parameters are (workingDirectory, stagedPlanPath) -
        // there is no String/URL parameter through which a request field could substitute a
        // different location, and RunnerRequest itself carries no filesystem-path field at all.
        Method m = TerraformCommandFactory.class.getMethod("showPlanJsonCommand",
                RunnerRequest.class, TerraformExecutableDescriptor.class, Path.class, Path.class, Duration.class);
        assertEquals(Path.class, m.getParameterTypes()[2]);
        assertEquals(Path.class, m.getParameterTypes()[3]);
    }

    @Test
    void planHashIsRecomputedImmediatelyBeforeLaunchAndTamperingIsDetected(@TempDir Path trustedRoot, @TempDir Path workspace) throws IOException {
        byte[] originalPlan = "original-plan-bytes".getBytes(StandardCharsets.UTF_8);
        String expectedHash = sha256Hex(originalPlan);
        Path stagedPlan = workspace.resolve("sha256-" + expectedHash + ".tfplan");
        Files.write(stagedPlan, originalPlan);

        Path binary = FakeExecutables.write(trustedRoot, "terraform", "#!/bin/sh\ntouch '" + trustedRoot.resolve("EXECUTED_MARKER") + "'\necho '{}'\nexit 0\n");
        Files.setPosixFilePermissions(binary, java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x"));
        var coordinator = coordinatorForBinary(binary, "1.6.6", trustedRoot);

        // Tamper with the staged file's content AFTER earlier pipeline verification would have run,
        // but before the coordinator's own final TOCTOU check.
        Files.write(stagedPlan, "TAMPERED-plan-bytes".getBytes(StandardCharsets.UTF_8));

        TerraformProcessEvidence evidence = coordinator.executeShowPlanJson(
                baseRequest("req-toctou", "a", expectedHash, "approval-1"), trustedIdentity(), workspace, stagedPlan, expectedHash);

        assertEquals(TerraformProcessState.BLOCKED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_PLAN_HASH_MISMATCH), evidence.reasonCodes());
        assertFalse(Files.exists(trustedRoot.resolve("EXECUTED_MARKER")), "the process must never have been launched once the TOCTOU check failed");
    }

    @Test
    void malformedShowJsonOutputNeverBecomesValidEvidence(@TempDir Path trustedRoot, @TempDir Path workspace) throws IOException {
        byte[] plan = "plan-bytes".getBytes(StandardCharsets.UTF_8);
        String hash = sha256Hex(plan);
        Path stagedPlan = workspace.resolve("sha256-" + hash + ".tfplan");
        Files.write(stagedPlan, plan);
        Path binary = FakeExecutables.terraformStub(trustedRoot, "terraform", "1.6.6", 0, "echo '{ not valid json'\nexit 0\n");
        var coordinator = coordinatorForBinary(binary, "1.6.6", trustedRoot);

        TerraformProcessEvidence evidence = coordinator.executeShowPlanJson(
                baseRequest("req-bad-json", "a", hash, "approval-1"), trustedIdentity(), workspace, stagedPlan, hash);

        assertEquals(TerraformProcessState.FAILED, evidence.processState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_OUTPUT_INVALID_JSON), evidence.reasonCodes());
    }

    @Test
    void showPlanJsonSucceedsAgainstAVerifiedStagedPlan(@TempDir Path trustedRoot, @TempDir Path workspace) throws IOException {
        byte[] plan = "plan-bytes".getBytes(StandardCharsets.UTF_8);
        String hash = sha256Hex(plan);
        Path stagedPlan = workspace.resolve("sha256-" + hash + ".tfplan");
        Files.write(stagedPlan, plan);
        Path binary = FakeExecutables.terraformStub(trustedRoot, "terraform", "1.6.6", 0, "echo '{\"format_version\":\"1.0\"}'\nexit 0\n");
        var coordinator = coordinatorForBinary(binary, "1.6.6", trustedRoot);

        TerraformProcessEvidence evidence = coordinator.executeShowPlanJson(
                baseRequest("req-show-ok", "a", hash, "approval-1"), trustedIdentity(), workspace, stagedPlan, hash);

        assertEquals(TerraformProcessState.SUCCEEDED, evidence.processState());
        assertEquals(hash, evidence.planSha256Observed());
    }

    // ===================== 36: FMT check =====================

    @Test
    void fmtCheckArgvAlwaysHasCheckAndNoColorAndNeverWrite(@TempDir Path trustedRoot, @TempDir Path workspace) throws IOException {
        Path binary = FakeExecutables.versionJson(trustedRoot, "terraform", "1.6.6", 0);
        TerraformCommandFactory factory = new TerraformCommandFactory(new TerraformProcessEnvironmentPolicy());
        var descriptor = new TerraformExecutableDescriptor(binary.toRealPath(), FakeExecutables.sha256Hex(binary), "1.6.6", trustedRoot.toRealPath());

        ControlledTerraformCommand command = factory.fmtCheckCommand(
                baseRequest("req-fmt", "a", "sha256:plan", "approval-1"), descriptor, workspace, Duration.ofSeconds(10));

        assertTrue(command.argv().contains("-check"));
        assertTrue(command.argv().contains("-no-color"));
        assertTrue(command.argv().contains("-recursive"));
        assertFalse(command.argv().stream().anyMatch(a -> a.startsWith("-write")));
    }

    @Test
    void fmtCheckNeverModifiesTheStagedConfigurationFile(@TempDir Path trustedRoot, @TempDir Path workspace) throws IOException {
        byte[] original = "resource \"terraform_data\" \"x\" {\n  input = \"y\"\n}\n".getBytes(StandardCharsets.UTF_8);
        RunnerWorkspaceManager manager = new RunnerWorkspaceManager(workspace);
        Path staged = manager.stageTerraformConfigFile(workspace, sha256Hex(original), original);
        Path binary = FakeExecutables.terraformStub(trustedRoot, "terraform", "1.6.6", 0, "exit 3\n"); // simulate "differences found"
        var coordinator = coordinatorForBinary(binary, "1.6.6", trustedRoot);

        coordinator.executeFmtCheck(baseRequest("req-fmt-safe", "a", "sha256:plan", "approval-1"), trustedIdentity(), workspace);

        assertArrayEquals(original, Files.readAllBytes(staged), "fmt -check must never modify the staged configuration file");
    }

    @Test
    void fmtCheckDifferencesAreADeterministicNonFailureOutcome(@TempDir Path trustedRoot, @TempDir Path workspace) throws IOException {
        Path binary = FakeExecutables.terraformStub(trustedRoot, "terraform", "1.6.6", 0, "exit 3\n");
        var coordinator = coordinatorForBinary(binary, "1.6.6", trustedRoot);

        TerraformProcessEvidence evidence = coordinator.executeFmtCheck(baseRequest("req-fmt-diff", "a", "sha256:plan", "approval-1"), trustedIdentity(), workspace);

        assertEquals(TerraformProcessState.COMMAND_REPORTED_DIFFERENCE, evidence.processState());
        assertTrue(evidence.reasonCodes().isEmpty(), "a difference report is not a failure and carries no failure reason code");
    }

    @Test
    void fmtCheckCleanExitSucceeds(@TempDir Path trustedRoot, @TempDir Path workspace) throws IOException {
        Path binary = FakeExecutables.terraformStub(trustedRoot, "terraform", "1.6.6", 0, "exit 0\n");
        var coordinator = coordinatorForBinary(binary, "1.6.6", trustedRoot);

        TerraformProcessEvidence evidence = coordinator.executeFmtCheck(baseRequest("req-fmt-clean", "a", "sha256:plan", "approval-1"), trustedIdentity(), workspace);

        assertEquals(TerraformProcessState.SUCCEEDED, evidence.processState());
    }

    @Test
    void realTerraformFmtCheckDetectsDifferencesAndCleanFilesSeparately(@TempDir Path trustedRoot, @TempDir Path workspace) throws IOException {
        Path realTerraform = findRealTerraform();
        Assumptions.assumeTrue(realTerraform != null, "no local terraform binary found - skipping real fmt integration test");
        Path binary = trustedRoot.resolve("terraform");
        Files.copy(realTerraform, binary);
        Files.setPosixFilePermissions(binary, java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x"));
        String hash = FakeExecutables.sha256Hex(binary);
        String actualVersion = detectRealTerraformVersion(binary);
        Assumptions.assumeTrue(actualVersion != null);

        var coordinator = new ControlledTerraformOperationCoordinator(
                new HostConfiguredTerraformExecutableProvider(binary, hash, actualVersion, trustedRoot, List.of()),
                new TerraformCommandFactory(new TerraformProcessEnvironmentPolicy()), new ControlledTerraformProcess(),
                Duration.ofSeconds(30), Duration.ofSeconds(30), Duration.ofSeconds(30));

        byte[] misformatted = "resource \"terraform_data\"    \"x\" {\ninput=\"y\"\n}\n".getBytes(StandardCharsets.UTF_8);
        RunnerWorkspaceManager manager = new RunnerWorkspaceManager(workspace);
        manager.stageTerraformConfigFile(workspace, sha256Hex(misformatted), misformatted);
        TerraformProcessEvidence diff = coordinator.executeFmtCheck(baseRequest("req-real-fmt-diff", "a", "sha256:plan", "approval-1"), trustedIdentity(), workspace);
        assertEquals(TerraformProcessState.COMMAND_REPORTED_DIFFERENCE, diff.processState());
    }

    // ===================== repository-source staging safety (amendment) =====================
    // stageTerraformConfigDirectory treats every byte of an untrusted repository checkout as
    // untrusted - only sourceRoot itself is vouched for by the caller.

    @Test
    void leafSymlinkInRepositorySourceIsRejected(@TempDir Path checkout, @TempDir Path outside, @TempDir Path workspace) throws IOException {
        Path secret = outside.resolve("secret.tf");
        Files.writeString(secret, "resource \"terraform_data\" \"secret\" {}\n");
        Path evilLink = checkout.resolve("escape.tf");
        try {
            Files.createSymbolicLink(evilLink, secret);
        } catch (UnsupportedOperationException | IOException e) {
            return; // platform/filesystem does not support symlinks - best-effort, matches Phase 2A precedent
        }

        TerraformConfigStagingResult result = new RunnerWorkspaceManager(workspace)
                .stageTerraformConfigDirectory(checkout, workspace, 1024 * 1024, 4 * 1024 * 1024);

        assertFalse(result.isSuccess());
        assertEquals(RunnerReasonCode.TERRAFORM_CONFIG_SOURCE_UNSAFE, result.failureReason());
        assertTrue(result.stagedFiles().isEmpty(), "a rejected source tree must stage nothing at all, not a partial set");
    }

    @Test
    void ancestorDirectorySymlinkInRepositorySourceIsRejected(@TempDir Path checkout, @TempDir Path outside, @TempDir Path workspace) throws IOException {
        Path outsideSubdir = outside.resolve("attacker-controlled");
        Files.createDirectory(outsideSubdir);
        Files.writeString(outsideSubdir.resolve("payload.tf"), "resource \"terraform_data\" \"payload\" {}\n");
        Path linkedSubdir = checkout.resolve("subdir");
        try {
            Files.createSymbolicLink(linkedSubdir, outsideSubdir);
        } catch (UnsupportedOperationException | IOException e) {
            return;
        }
        // A normal, safe file also present at the top level - proves the rejection is about the
        // symlinked subdirectory specifically, not a blanket failure that would trip on anything.
        Files.writeString(checkout.resolve("main.tf"), "resource \"terraform_data\" \"main\" {}\n");

        TerraformConfigStagingResult result = new RunnerWorkspaceManager(workspace)
                .stageTerraformConfigDirectory(checkout, workspace, 1024 * 1024, 4 * 1024 * 1024);

        assertFalse(result.isSuccess());
        assertEquals(RunnerReasonCode.TERRAFORM_CONFIG_SOURCE_UNSAFE, result.failureReason());
        assertTrue(result.stagedFiles().isEmpty(), "the whole attempt must be rejected, not just the symlinked subdirectory");
    }

    @Test
    void ordinaryConfigFilesBeneathTheCheckoutRootAreStagedSafely(@TempDir Path checkout, @TempDir Path workspace) throws IOException {
        byte[] mainTf = "resource \"terraform_data\" \"main\" {}\n".getBytes(StandardCharsets.UTF_8);
        Files.write(checkout.resolve("main.tf"), mainTf);
        Path subdir = checkout.resolve("modules/nested");
        Files.createDirectories(subdir);
        byte[] nestedTf = "resource \"terraform_data\" \"nested\" {}\n".getBytes(StandardCharsets.UTF_8);
        Files.write(subdir.resolve("nested.tf"), nestedTf);
        Files.writeString(checkout.resolve("README.md"), "not a terraform file - must be ignored, not rejected");

        TerraformConfigStagingResult result = new RunnerWorkspaceManager(workspace)
                .stageTerraformConfigDirectory(checkout, workspace, 1024 * 1024, 4 * 1024 * 1024);

        assertTrue(result.isSuccess());
        assertEquals(2, result.stagedFiles().size());
        Set<String> stagedContents = new java.util.HashSet<>();
        for (Path staged : result.stagedFiles()) {
            stagedContents.add(new String(Files.readAllBytes(staged), StandardCharsets.UTF_8));
        }
        assertTrue(stagedContents.contains(new String(mainTf, StandardCharsets.UTF_8)));
        assertTrue(stagedContents.contains(new String(nestedTf, StandardCharsets.UTF_8)));
    }

    @Test
    void oversizedIndividualConfigFileIsRejectedDeterministically(@TempDir Path checkout, @TempDir Path workspace) throws IOException {
        byte[] tooLarge = "x".repeat(2000).getBytes(StandardCharsets.UTF_8);
        Files.write(checkout.resolve("huge.tf"), tooLarge);

        TerraformConfigStagingResult result = new RunnerWorkspaceManager(workspace)
                .stageTerraformConfigDirectory(checkout, workspace, 1000, 4 * 1024 * 1024);

        assertFalse(result.isSuccess());
        assertEquals(RunnerReasonCode.TERRAFORM_CONFIG_SIZE_LIMIT_EXCEEDED, result.failureReason());
    }

    @Test
    void oversizedAggregateConfigSizeIsRejectedDeterministically(@TempDir Path checkout, @TempDir Path workspace) throws IOException {
        byte[] chunk = "x".repeat(600).getBytes(StandardCharsets.UTF_8);
        Files.write(checkout.resolve("a.tf"), chunk);
        Files.write(checkout.resolve("b.tf"), chunk);
        Files.write(checkout.resolve("c.tf"), chunk);

        TerraformConfigStagingResult result = new RunnerWorkspaceManager(workspace)
                .stageTerraformConfigDirectory(checkout, workspace, 1000, 1000);

        assertFalse(result.isSuccess());
        assertEquals(RunnerReasonCode.TERRAFORM_CONFIG_SIZE_LIMIT_EXCEEDED, result.failureReason());
    }

    // ===================== 37: source scan =====================

    @Test
    void processBuilderAppearsOnlyInControlledTerraformProcess() throws IOException {
        Path sourceDir = Path.of("src/main/java/com/iacagent/iacagent/runner");
        if (!Files.isDirectory(sourceDir)) {
            return;
        }
        // Phase 2B-4 amendment: comments are stripped before scanning, same lesson already recorded
        // for Phase 2B-2's System.getenv() scan and Phase 2B-3's LegacyExecutionSurfaceTests - this
        // phase's own extensive javadoc explains "terraform init"/"terraform validate" by name in
        // prose, which would otherwise trip this literal scan even though no actual argv-building
        // code ever concatenates those two words (TerraformCommandFactory always builds "init" and
        // "validate" as SEPARATE List.of(...) elements from the executable path, never joined with
        // "terraform " into one string) - the forbidden two-word phrases below remain meaningful for
        // any future code that DID naively concatenate a command line as a single string.
        List<String> forbiddenEverywhere = List.of(
                "Runtime.getRuntime().exec", "Runtime.exec", "/bin/sh", "\"bash\"", "bash -c", "cmd.exe", "powershell",
                "terraform plan", "terraform apply", "terraform destroy",
                "terraform import", "terraform state", "terraform force-unlock", "terraform taint", "terraform untaint",
                "terraform refresh", "terraform workspace");
        try (var files = Files.walk(sourceDir)) {
            for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                String content = stripJavaComments(Files.readString(file));
                boolean isTheProcessBoundary = file.getFileName().toString().equals("ControlledTerraformProcess.java");
                if (!isTheProcessBoundary) {
                    assertFalse(content.contains("ProcessBuilder"), file + " must not reference ProcessBuilder");
                }
                for (String literal : forbiddenEverywhere) {
                    assertFalse(content.contains(literal), file + " must not contain \"" + literal + "\"");
                }
            }
        }
    }

    private static String stripJavaComments(String source) {
        String noBlockComments = source.replaceAll("(?s)/\\*.*?\\*/", "");
        return noBlockComments.replaceAll("(?m)//.*$", "");
    }

    // ===================== ControlledRunner integration (no approval/ledger bypass) =====================

    @Test
    void controlledTerraformOperationCoordinatorIsNotPublic() {
        assertFalse(Modifier.isPublic(ControlledTerraformOperationCoordinator.class.getModifiers()),
                "the coordinator must not be reachable from outside this package - only ControlledRunner may call it");
    }

    @Test
    void terraformVersionSucceedsEndToEndThroughControlledRunner(@TempDir Path root, @TempDir Path trustedRoot) throws IOException {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String planSha = sha256Hex("plan".getBytes(StandardCharsets.UTF_8));
        String approvalId = issueValidApproval(repo, planSha);
        Path binary = FakeExecutables.versionJson(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED, 0);
        ControlledRunner runner = runnerWithTerraform(root, repo, binary, TERRAFORM_VERSION_EXPECTED, trustedRoot);

        RunnerEvidence evidence = runner.execute(baseRequest("req-e2e-version", "artifact-1", planSha, approvalId));

        assertEquals(RunnerState.TERRAFORM_PROCESS_COMPLETED, evidence.finalState());
        assertNotNull(evidence.terraformProcessEvidence());
        assertEquals(TerraformProcessState.SUCCEEDED, evidence.terraformProcessEvidence().processState());
    }

    @Test
    void terraformFmtCheckSucceedsEndToEndThroughControlledRunner(@TempDir Path root, @TempDir Path trustedRoot) throws IOException {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        byte[] configBytes = "resource \"terraform_data\" \"x\" {}\n".getBytes(StandardCharsets.UTF_8);
        String configSha = sha256Hex(configBytes);
        String approvalId = issueValidApproval(repo, configSha);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(new StoredArtifact("config-1", configBytes, configBytes.length, configSha, new ArtifactProvenance("test")));
        Path binary = FakeExecutables.terraformStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED, 0, "exit 0\n");
        ControlledRunner runner = runnerWithTerraform(root, repo, artifactStore, binary, trustedRoot);

        RunnerEvidence evidence = runner.execute(withOperation(baseRequest("req-e2e-fmt", "config-1", configSha, approvalId), RunnerOperation.TERRAFORM_FMT_CHECK));

        assertEquals(RunnerState.TERRAFORM_PROCESS_COMPLETED, evidence.finalState());
        assertEquals(TerraformProcessState.SUCCEEDED, evidence.terraformProcessEvidence().processState());
    }

    @Test
    void terraformShowPlanJsonSucceedsEndToEndThroughControlledRunner(@TempDir Path root, @TempDir Path trustedRoot) throws IOException {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        byte[] planBytes = "plan-bytes".getBytes(StandardCharsets.UTF_8);
        String planSha = sha256Hex(planBytes);
        String approvalId = issueValidApproval(repo, planSha);
        InMemoryRunnerArtifactStore artifactStore = new InMemoryRunnerArtifactStore();
        artifactStore.stage(new StoredArtifact("plan-1", planBytes, planBytes.length, planSha, new ArtifactProvenance("test")));
        Path binary = FakeExecutables.terraformStub(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED, 0, "echo '{\"format_version\":\"1.0\"}'\nexit 0\n");
        ControlledRunner runner = runnerWithTerraform(root, repo, artifactStore, binary, trustedRoot);

        RunnerEvidence evidence = runner.execute(withOperation(baseRequest("req-e2e-show", "plan-1", planSha, approvalId), RunnerOperation.TERRAFORM_SHOW_PLAN_JSON));

        assertEquals(RunnerState.TERRAFORM_PROCESS_COMPLETED, evidence.finalState());
        assertEquals(planSha, evidence.terraformProcessEvidence().planSha256Observed());
    }

    @Test
    void duplicateTerraformRequestStillBlocksViaTheExistingReplayProtection(@TempDir Path root, @TempDir Path trustedRoot) throws IOException {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String planSha = sha256Hex("plan".getBytes(StandardCharsets.UTF_8));
        String approvalId = issueValidApproval(repo, planSha);
        Path binary = FakeExecutables.versionJson(trustedRoot, "terraform", TERRAFORM_VERSION_EXPECTED, 0);
        ControlledRunner runner = runnerWithTerraform(root, repo, binary, TERRAFORM_VERSION_EXPECTED, trustedRoot);
        RunnerRequest request = baseRequest("req-e2e-dup", "artifact-1", planSha, approvalId);

        RunnerEvidence first = runner.execute(request);
        RunnerEvidence second = runner.execute(request);

        assertEquals(RunnerState.TERRAFORM_PROCESS_COMPLETED, first.finalState());
        assertEquals(RunnerState.BLOCKED, second.finalState());
        assertEquals(List.of(RunnerReasonCode.DUPLICATE_RUNNER_REQUEST), second.reasonCodes());
    }

    @Test
    void runnerNotWiredForTerraformBlocksRatherThanThrowing(@TempDir Path root) {
        InMemoryApprovalRepository repo = new InMemoryApprovalRepository();
        String planSha = sha256Hex("plan".getBytes(StandardCharsets.UTF_8));
        String approvalId = issueValidApproval(repo, planSha);
        ControlledRunner runner = new ControlledRunner(
                new StaticRunnerIdentityProvider(trustedIdentity()),
                ALLOWED_RUNNER_CLASSES,
                new RepositoryBackedApprovalProvider(repo),
                new InMemoryRunnerArtifactStore(),
                new StaticRunnerToolchainContext(TERRAFORM_VERSION_EXPECTED, PROVIDER_LOCK_HASH),
                new RunnerWorkspaceManager(root),
                new InMemoryRunnerLedgerRepository(),
                new MutableClock(NOW));

        RunnerEvidence evidence = runner.execute(baseRequest("req-no-terraform", "artifact-1", planSha, approvalId));

        assertEquals(RunnerState.BLOCKED, evidence.finalState());
        assertEquals(List.of(RunnerReasonCode.TERRAFORM_OPERATION_NOT_ALLOWED), evidence.reasonCodes());
    }

    // ===================== helpers =====================

    private ControlledTerraformOperationCoordinator coordinatorFor(TerraformExecutableProvider provider) {
        return new ControlledTerraformOperationCoordinator(
                provider, new TerraformCommandFactory(new TerraformProcessEnvironmentPolicy()), new ControlledTerraformProcess(),
                Duration.ofSeconds(10), Duration.ofSeconds(10), Duration.ofSeconds(10));
    }

    private ControlledTerraformOperationCoordinator coordinatorForBinary(Path binary, String expectedVersion, Path trustedRoot) throws IOException {
        var provider = new HostConfiguredTerraformExecutableProvider(binary, FakeExecutables.sha256Hex(binary), expectedVersion, trustedRoot, List.of());
        return coordinatorFor(provider);
    }

    private ControlledTerraformOperationCoordinator fakeVersionCoordinator(Path trustedRoot, String reportedVersion, int exitCode, String expectedVersion) throws IOException {
        Path binary = FakeExecutables.versionJson(trustedRoot, "terraform", reportedVersion, exitCode);
        return coordinatorForBinary(binary, expectedVersion, trustedRoot);
    }

    private ControlledRunner runnerWithTerraform(Path root, InMemoryApprovalRepository repo, Path binary, String expectedVersion, Path trustedRoot) throws IOException {
        return runnerWithTerraform(root, repo, new InMemoryRunnerArtifactStore(), binary, trustedRoot, expectedVersion);
    }

    private ControlledRunner runnerWithTerraform(Path root, InMemoryApprovalRepository repo, InMemoryRunnerArtifactStore artifactStore, Path binary, Path trustedRoot) throws IOException {
        return runnerWithTerraform(root, repo, artifactStore, binary, trustedRoot, TERRAFORM_VERSION_EXPECTED);
    }

    private ControlledRunner runnerWithTerraform(Path root, InMemoryApprovalRepository repo, InMemoryRunnerArtifactStore artifactStore,
                                                  Path binary, Path trustedRoot, String expectedVersion) throws IOException {
        var provider = new HostConfiguredTerraformExecutableProvider(binary, FakeExecutables.sha256Hex(binary), expectedVersion, trustedRoot, List.of(root));
        var coordinator = coordinatorFor(provider);
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

    private static Path findRealTerraform() {
        for (String candidate : List.of("/opt/homebrew/bin/terraform", "/usr/local/bin/terraform", "/usr/bin/terraform")) {
            Path path = Path.of(candidate);
            if (Files.isRegularFile(path) && Files.isExecutable(path)) {
                return path;
            }
        }
        return null;
    }

    private static String detectRealTerraformVersion(Path binary) {
        try {
            Process process = new ProcessBuilder(binary.toString(), "version", "-json").redirectErrorStream(false).start();
            process.getOutputStream().close();
            byte[] output = process.getInputStream().readAllBytes();
            process.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            tools.jackson.databind.JsonNode root = new tools.jackson.databind.ObjectMapper().readTree(output);
            tools.jackson.databind.JsonNode versionNode = root.path("terraform_version");
            return versionNode.isMissingNode() || versionNode.isNull() ? null : versionNode.asText();
        } catch (IOException | InterruptedException | RuntimeException e) {
            return null;
        }
    }
}
