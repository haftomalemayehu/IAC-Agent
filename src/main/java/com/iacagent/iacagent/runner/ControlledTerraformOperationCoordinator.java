package com.iacagent.iacagent.runner;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;

/**
 * Orchestrates one Terraform process-boundary attempt: verify the trusted executable (path-safety,
 * SHA-256, and - for {@code TERRAFORM_FMT_CHECK}/{@code TERRAFORM_SHOW_PLAN_JSON} - a bound
 * Terraform version attestation), build the closed command, launch it via
 * {@link ControlledTerraformProcess}, and interpret the raw {@link TerraformProcessResult} into a
 * {@link TerraformProcessEvidence} - the only place that interpretation (JSON parsing, version
 * comparison, per-operation exit-code semantics) happens. Called only from
 * {@link ControlledRunner#execute}, after the SAME durable claim, identity, approval, and (where
 * applicable) artifact/context validation every other {@link RunnerOperation} already goes
 * through - there is no method here a caller could use to skip that pipeline, and this class is
 * itself package-private, unreachable from outside {@code com.iacagent.iacagent.runner}
 * (see {@code Phase2b3Tests#controlledTerraformOperationCoordinatorIsNotPublic}).
 *
 * <h2>Version binding (amended after review)</h2>
 * An earlier revision let {@code TERRAFORM_FMT_CHECK}/{@code TERRAFORM_SHOW_PLAN_JSON} rely on the
 * executable's SHA-256 match alone, reasoning that a hash match to a known release binary is at
 * least as strong a version proof as a self-reported version string. Review correctly rejected that:
 * {@link TerraformExecutableDescriptor#expectedVersion()} exists precisely so a hash-trusted binary
 * that reports an unexpected version still blocks, and skipping that check for two of the three
 * operations left it purely decorative for them. Every operation now requires a
 * {@link VerifiedTerraformExecutable} attestation before it may launch its own command -
 * {@link #obtainVerifiedExecutable} establishes one (by actually running {@code terraform
 * version -json} and comparing the result) whenever no still-valid cached attestation exists for
 * the CURRENT hash of the CURRENT executable, and reuses a valid one otherwise, so a bound version
 * is never optional but a fresh Terraform process also isn't launched on every single call for an
 * unchanged binary. The path-safety and SHA-256 checks inside {@link #verifyExecutable} still run
 * fresh on every single call, immediately before whichever command actually launches - the
 * attestation only ever shortcuts the VERSION-checking process, never the hash recheck.
 */
final class ControlledTerraformOperationCoordinator {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final TerraformExecutableProvider executableProvider;
    private final TerraformCommandFactory commandFactory;
    private final ControlledTerraformProcess process;
    private final Duration versionTimeout;
    private final Duration fmtCheckTimeout;
    private final Duration showPlanJsonTimeout;

    private final Object attestationLock = new Object();
    private VerifiedTerraformExecutable cachedAttestation;

    ControlledTerraformOperationCoordinator(
            TerraformExecutableProvider executableProvider,
            TerraformCommandFactory commandFactory,
            ControlledTerraformProcess process,
            Duration versionTimeout,
            Duration fmtCheckTimeout,
            Duration showPlanJsonTimeout) {
        this.executableProvider = require(executableProvider, "executableProvider");
        this.commandFactory = require(commandFactory, "commandFactory");
        this.process = require(process, "process");
        this.versionTimeout = requirePositive(versionTimeout, "versionTimeout");
        this.fmtCheckTimeout = requirePositive(fmtCheckTimeout, "fmtCheckTimeout");
        this.showPlanJsonTimeout = requirePositive(showPlanJsonTimeout, "showPlanJsonTimeout");
    }

    private static <T> T require(T value, String name) {
        if (value == null) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }

    private static Duration requirePositive(Duration value, String name) {
        if (value == null || value.isNegative() || value.isZero()) {
            throw new IllegalArgumentException(name + " must be a positive duration");
        }
        return value;
    }

    /** Path-safety + SHA-256 only - no version claim. Always re-run fresh, on every call. */
    private record ExecutableVerification(TerraformExecutableDescriptor descriptor, String observedSha256, RunnerReasonCode failureReason) {
        boolean isVerified() {
            return descriptor != null;
        }
    }

    private ExecutableVerification verifyExecutable() {
        TerraformExecutableResolution resolution = executableProvider.resolve();
        if (resolution.outcome() != TerraformExecutableResolutionOutcome.RESOLVED) {
            RunnerReasonCode reason = switch (resolution.outcome()) {
                case NOT_FOUND -> RunnerReasonCode.TERRAFORM_EXECUTABLE_NOT_FOUND;
                case UNTRUSTED_PATH -> RunnerReasonCode.TERRAFORM_EXECUTABLE_UNTRUSTED;
                case NOT_EXECUTABLE -> RunnerReasonCode.TERRAFORM_EXECUTABLE_NOT_EXECUTABLE;
                case RESOLVED -> throw new IllegalStateException("unreachable");
            };
            return new ExecutableVerification(null, null, reason);
        }
        TerraformExecutableDescriptor descriptor = resolution.descriptor();
        String observedSha256;
        try {
            observedSha256 = sha256Hex(Files.readAllBytes(descriptor.executablePath()));
        } catch (IOException e) {
            return new ExecutableVerification(null, null, RunnerReasonCode.TERRAFORM_EXECUTABLE_NOT_FOUND);
        }
        if (!observedSha256.equals(descriptor.expectedSha256())) {
            return new ExecutableVerification(null, observedSha256, RunnerReasonCode.TERRAFORM_EXECUTABLE_HASH_MISMATCH);
        }
        return new ExecutableVerification(descriptor, observedSha256, null);
    }

    /** Path-safety + SHA-256 (always fresh) PLUS a bound, verified Terraform version - established
     * by actually running {@code version -json} unless a cached attestation for this exact
     * (path, hash) pair is still valid. {@code observedVersion} is populated even on a
     * {@code TERRAFORM_VERSION_MISMATCH} failure, so callers can still record what was actually
     * observed. */
    private record AttestationOutcome(TerraformExecutableDescriptor descriptor, String observedSha256, String observedVersion, RunnerReasonCode failureReason) {
        boolean isVerified() {
            return descriptor != null;
        }
    }

    private AttestationOutcome obtainVerifiedExecutable(RunnerRequest request, Path workspace) {
        ExecutableVerification verification = verifyExecutable();
        if (!verification.isVerified()) {
            return new AttestationOutcome(null, verification.observedSha256(), null, verification.failureReason());
        }
        synchronized (attestationLock) {
            VerifiedTerraformExecutable cached = cachedAttestation;
            if (cached != null
                    && cached.realPath().equals(verification.descriptor().executablePath())
                    && cached.observedSha256().equals(verification.observedSha256())) {
                return new AttestationOutcome(verification.descriptor(), verification.observedSha256(), cached.observedVersion(), null);
            }
            ControlledTerraformCommand versionCommand = commandFactory.versionCommand(request, verification.descriptor(), workspace, versionTimeout);
            TerraformProcessResult result = process.execute(versionCommand);
            if (result.timedOut()) {
                return new AttestationOutcome(null, verification.observedSha256(), null, RunnerReasonCode.TERRAFORM_PROCESS_TIMEOUT);
            }
            if (result.outputLimitExceeded()) {
                return new AttestationOutcome(null, verification.observedSha256(), null, RunnerReasonCode.TERRAFORM_OUTPUT_LIMIT_EXCEEDED);
            }
            if (result.startFailed()) {
                return new AttestationOutcome(null, verification.observedSha256(), null, RunnerReasonCode.TERRAFORM_PROCESS_START_FAILED);
            }
            if (result.exitCode() != 0) {
                return new AttestationOutcome(null, verification.observedSha256(), null, RunnerReasonCode.TERRAFORM_PROCESS_EXIT_FAILED);
            }
            String observedVersion = parseTerraformVersion(result.stdout());
            if (observedVersion == null) {
                return new AttestationOutcome(null, verification.observedSha256(), null, RunnerReasonCode.TERRAFORM_VERSION_OUTPUT_INVALID);
            }
            if (!observedVersion.equals(verification.descriptor().expectedVersion())) {
                return new AttestationOutcome(null, verification.observedSha256(), observedVersion, RunnerReasonCode.TERRAFORM_VERSION_MISMATCH);
            }
            cachedAttestation = new VerifiedTerraformExecutable(
                    verification.descriptor().executablePath(), verification.observedSha256(), observedVersion, Instant.now());
            return new AttestationOutcome(verification.descriptor(), verification.observedSha256(), observedVersion, null);
        }
    }

    TerraformProcessEvidence executeVersion(RunnerRequest request, RunnerIdentity identity, Path workspace) {
        Instant startedAt = Instant.now();
        ExecutableVerification verification = verifyExecutable();
        if (!verification.isVerified()) {
            return blocked(request, identity, ControlledTerraformOperation.TERRAFORM_VERSION, verification.failureReason(),
                    null, verification.observedSha256(), null, null, null, workspace, startedAt);
        }
        ControlledTerraformCommand command = commandFactory.versionCommand(request, verification.descriptor(), workspace, versionTimeout);
        TerraformProcessResult result = process.execute(command);
        return interpretVersion(request, identity, verification.descriptor(), verification.observedSha256(), command, result, workspace, startedAt);
    }

    TerraformProcessEvidence executeFmtCheck(RunnerRequest request, RunnerIdentity identity, Path workspace) {
        Instant startedAt = Instant.now();
        AttestationOutcome attestation = obtainVerifiedExecutable(request, workspace);
        if (!attestation.isVerified()) {
            return blocked(request, identity, ControlledTerraformOperation.TERRAFORM_FMT_CHECK, attestation.failureReason(),
                    null, attestation.observedSha256(), attestation.observedVersion(), null, null, workspace, startedAt);
        }
        Path revalidatedWorkspace;
        try {
            revalidatedWorkspace = workspace.toRealPath();
        } catch (IOException e) {
            return blocked(request, identity, ControlledTerraformOperation.TERRAFORM_FMT_CHECK, RunnerReasonCode.TERRAFORM_WORKING_DIRECTORY_UNSAFE,
                    attestation.descriptor(), attestation.observedSha256(), attestation.observedVersion(), null, null, workspace, startedAt);
        }
        ControlledTerraformCommand command = commandFactory.fmtCheckCommand(request, attestation.descriptor(), revalidatedWorkspace, fmtCheckTimeout);
        TerraformProcessResult result = process.execute(command);
        return interpretFmtCheck(request, identity, attestation.descriptor(), attestation.observedSha256(), attestation.observedVersion(), command, result, workspace, startedAt);
    }

    TerraformProcessEvidence executeShowPlanJson(
            RunnerRequest request, RunnerIdentity identity, Path workspace, Path stagedPlanPath, String expectedPlanSha256) {
        Instant startedAt = Instant.now();
        // Plan-hash TOCTOU check runs FIRST, before the (possibly process-launching) executable
        // attestation - it is a pure hash comparison with no process cost, so failing fast here
        // means a tampered plan never triggers even the attestation-establishing version check,
        // let alone the actual `show` launch.
        String observedPlanSha256;
        try {
            observedPlanSha256 = sha256Hex(Files.readAllBytes(stagedPlanPath));
        } catch (IOException e) {
            return blocked(request, identity, ControlledTerraformOperation.TERRAFORM_SHOW_PLAN_JSON, RunnerReasonCode.TERRAFORM_PLAN_HASH_MISMATCH,
                    null, null, null, expectedPlanSha256, null, workspace, startedAt);
        }
        if (!observedPlanSha256.equals(expectedPlanSha256)) {
            return blocked(request, identity, ControlledTerraformOperation.TERRAFORM_SHOW_PLAN_JSON, RunnerReasonCode.TERRAFORM_PLAN_HASH_MISMATCH,
                    null, null, null, expectedPlanSha256, observedPlanSha256, workspace, startedAt);
        }
        AttestationOutcome attestation = obtainVerifiedExecutable(request, workspace);
        if (!attestation.isVerified()) {
            return blocked(request, identity, ControlledTerraformOperation.TERRAFORM_SHOW_PLAN_JSON, attestation.failureReason(),
                    null, attestation.observedSha256(), attestation.observedVersion(), expectedPlanSha256, observedPlanSha256, workspace, startedAt);
        }
        ControlledTerraformCommand command =
                commandFactory.showPlanJsonCommand(request, attestation.descriptor(), workspace, stagedPlanPath, showPlanJsonTimeout);
        TerraformProcessResult result = process.execute(command);
        return interpretShowPlanJson(request, identity, attestation.descriptor(), attestation.observedSha256(), attestation.observedVersion(),
                expectedPlanSha256, observedPlanSha256, command, result, workspace, startedAt);
    }

    private TerraformProcessEvidence interpretVersion(
            RunnerRequest request, RunnerIdentity identity, TerraformExecutableDescriptor descriptor, String observedExecutableSha256,
            ControlledTerraformCommand command, TerraformProcessResult result, Path workspace, Instant startedAt) {
        if (result.timedOut()) {
            return terminal(request, identity, command, result, TerraformProcessState.TIMED_OUT,
                    List.of(RunnerReasonCode.TERRAFORM_PROCESS_TIMEOUT), descriptor, observedExecutableSha256, null, workspace, startedAt);
        }
        if (result.outputLimitExceeded()) {
            return terminal(request, identity, command, result, TerraformProcessState.OUTPUT_LIMIT_EXCEEDED,
                    List.of(RunnerReasonCode.TERRAFORM_OUTPUT_LIMIT_EXCEEDED), descriptor, observedExecutableSha256, null, workspace, startedAt);
        }
        if (result.startFailed()) {
            return terminal(request, identity, command, result, TerraformProcessState.BLOCKED,
                    List.of(RunnerReasonCode.TERRAFORM_PROCESS_START_FAILED), descriptor, observedExecutableSha256, null, workspace, startedAt);
        }
        if (result.exitCode() != 0) {
            return terminal(request, identity, command, result, TerraformProcessState.FAILED,
                    List.of(RunnerReasonCode.TERRAFORM_PROCESS_EXIT_FAILED), descriptor, observedExecutableSha256, null, workspace, startedAt);
        }
        String observedVersion = parseTerraformVersion(result.stdout());
        if (observedVersion == null) {
            return terminal(request, identity, command, result, TerraformProcessState.FAILED,
                    List.of(RunnerReasonCode.TERRAFORM_VERSION_OUTPUT_INVALID), descriptor, observedExecutableSha256, null, workspace, startedAt);
        }
        if (!observedVersion.equals(descriptor.expectedVersion())) {
            return terminal(request, identity, command, result, TerraformProcessState.FAILED,
                    List.of(RunnerReasonCode.TERRAFORM_VERSION_MISMATCH), descriptor, observedExecutableSha256, observedVersion, workspace, startedAt);
        }
        // Explicit TERRAFORM_VERSION success also refreshes the shared attestation cache, so a
        // subsequent FMT_CHECK/SHOW_PLAN_JSON call against the same (still-unchanged) binary does
        // not need to launch its own redundant version-check process.
        synchronized (attestationLock) {
            cachedAttestation = new VerifiedTerraformExecutable(descriptor.executablePath(), observedExecutableSha256, observedVersion, Instant.now());
        }
        return terminal(request, identity, command, result, TerraformProcessState.SUCCEEDED,
                List.of(), descriptor, observedExecutableSha256, observedVersion, workspace, startedAt);
    }

    private TerraformProcessEvidence interpretFmtCheck(
            RunnerRequest request, RunnerIdentity identity, TerraformExecutableDescriptor descriptor, String observedExecutableSha256,
            String observedVersion, ControlledTerraformCommand command, TerraformProcessResult result, Path workspace, Instant startedAt) {
        if (result.timedOut()) {
            return terminal(request, identity, command, result, TerraformProcessState.TIMED_OUT,
                    List.of(RunnerReasonCode.TERRAFORM_PROCESS_TIMEOUT), descriptor, observedExecutableSha256, observedVersion, workspace, startedAt);
        }
        if (result.outputLimitExceeded()) {
            return terminal(request, identity, command, result, TerraformProcessState.OUTPUT_LIMIT_EXCEEDED,
                    List.of(RunnerReasonCode.TERRAFORM_OUTPUT_LIMIT_EXCEEDED), descriptor, observedExecutableSha256, observedVersion, workspace, startedAt);
        }
        if (result.startFailed()) {
            return terminal(request, identity, command, result, TerraformProcessState.BLOCKED,
                    List.of(RunnerReasonCode.TERRAFORM_PROCESS_START_FAILED), descriptor, observedExecutableSha256, observedVersion, workspace, startedAt);
        }
        // fmt -check: exit 0 = already formatted; any nonzero exit is treated as a deterministic
        // "formatting differences reported" outcome, never as a generic command-execution failure -
        // see docs/phase-2b3-controlled-terraform-process.md's FMT_CHECK section for the documented
        // limitation that this does not attempt to distinguish "differences" from "a real fmt error"
        // by exit code alone (Terraform's own exit-code contract for this is not stable enough
        // across versions to rely on further without invoking real Terraform to verify).
        TerraformProcessState state = result.exitCode() == 0 ? TerraformProcessState.SUCCEEDED : TerraformProcessState.COMMAND_REPORTED_DIFFERENCE;
        return terminal(request, identity, command, result, state, List.of(), descriptor, observedExecutableSha256, observedVersion, workspace, startedAt);
    }

    private TerraformProcessEvidence interpretShowPlanJson(
            RunnerRequest request, RunnerIdentity identity, TerraformExecutableDescriptor descriptor, String observedExecutableSha256,
            String observedVersion, String expectedPlanSha256, String observedPlanSha256, ControlledTerraformCommand command,
            TerraformProcessResult result, Path workspace, Instant startedAt) {
        if (result.timedOut()) {
            return terminalWithPlan(request, identity, command, result, TerraformProcessState.TIMED_OUT,
                    List.of(RunnerReasonCode.TERRAFORM_PROCESS_TIMEOUT), descriptor, observedExecutableSha256, observedVersion,
                    expectedPlanSha256, observedPlanSha256, workspace, startedAt);
        }
        if (result.outputLimitExceeded()) {
            return terminalWithPlan(request, identity, command, result, TerraformProcessState.OUTPUT_LIMIT_EXCEEDED,
                    List.of(RunnerReasonCode.TERRAFORM_OUTPUT_LIMIT_EXCEEDED), descriptor, observedExecutableSha256, observedVersion,
                    expectedPlanSha256, observedPlanSha256, workspace, startedAt);
        }
        if (result.startFailed()) {
            return terminalWithPlan(request, identity, command, result, TerraformProcessState.BLOCKED,
                    List.of(RunnerReasonCode.TERRAFORM_PROCESS_START_FAILED), descriptor, observedExecutableSha256, observedVersion,
                    expectedPlanSha256, observedPlanSha256, workspace, startedAt);
        }
        if (result.exitCode() != 0) {
            return terminalWithPlan(request, identity, command, result, TerraformProcessState.FAILED,
                    List.of(RunnerReasonCode.TERRAFORM_PROCESS_EXIT_FAILED), descriptor, observedExecutableSha256, observedVersion,
                    expectedPlanSha256, observedPlanSha256, workspace, startedAt);
        }
        if (!isValidJson(result.stdout())) {
            return terminalWithPlan(request, identity, command, result, TerraformProcessState.FAILED,
                    List.of(RunnerReasonCode.TERRAFORM_OUTPUT_INVALID_JSON), descriptor, observedExecutableSha256, observedVersion,
                    expectedPlanSha256, observedPlanSha256, workspace, startedAt);
        }
        return terminalWithPlan(request, identity, command, result, TerraformProcessState.SUCCEEDED,
                List.of(), descriptor, observedExecutableSha256, observedVersion, expectedPlanSha256, observedPlanSha256, workspace, startedAt);
    }

    private TerraformProcessEvidence blocked(
            RunnerRequest request, RunnerIdentity identity, ControlledTerraformOperation operation, RunnerReasonCode reason,
            TerraformExecutableDescriptor descriptor, String observedExecutableSha256, String observedVersion,
            String expectedPlanSha256, String observedPlanSha256, Path workspace, Instant startedAt) {
        Instant completedAt = Instant.now();
        return new TerraformProcessEvidence(
                request.runnerRequestId(),
                identity == null ? null : identity.runnerId(),
                operation,
                workspace == null ? null : workspace.toString(),
                descriptor == null ? null : descriptor.expectedSha256(),
                observedExecutableSha256,
                descriptor == null ? null : descriptor.expectedVersion(),
                observedVersion,
                workspace == null ? null : workspace.toString(),
                expectedPlanSha256,
                observedPlanSha256,
                operation.name(),
                null,
                false,
                TerraformProcessState.BLOCKED,
                List.of(reason),
                0, 0, emptyHash(), emptyHash(),
                startedAt, completedAt);
    }

    private TerraformProcessEvidence terminal(
            RunnerRequest request, RunnerIdentity identity, ControlledTerraformCommand command, TerraformProcessResult result,
            TerraformProcessState state, List<RunnerReasonCode> reasonCodes, TerraformExecutableDescriptor descriptor,
            String observedExecutableSha256, String observedVersion, Path workspace, Instant startedAt) {
        return new TerraformProcessEvidence(
                request.runnerRequestId(),
                identity == null ? null : identity.runnerId(),
                command.operation(),
                descriptor.executablePath().toString(),
                descriptor.expectedSha256(),
                observedExecutableSha256,
                descriptor.expectedVersion(),
                observedVersion,
                workspace.toString(),
                null,
                null,
                command.operation().name(),
                result.exitCode(),
                result.timedOut(),
                state,
                reasonCodes,
                result.stdoutSize(), result.stderrSize(), result.stdoutSha256(), result.stderrSha256(),
                startedAt, result.completedAt());
    }

    private TerraformProcessEvidence terminalWithPlan(
            RunnerRequest request, RunnerIdentity identity, ControlledTerraformCommand command, TerraformProcessResult result,
            TerraformProcessState state, List<RunnerReasonCode> reasonCodes, TerraformExecutableDescriptor descriptor,
            String observedExecutableSha256, String observedVersion, String expectedPlanSha256, String observedPlanSha256,
            Path workspace, Instant startedAt) {
        return new TerraformProcessEvidence(
                request.runnerRequestId(),
                identity == null ? null : identity.runnerId(),
                command.operation(),
                descriptor.executablePath().toString(),
                descriptor.expectedSha256(),
                observedExecutableSha256,
                descriptor.expectedVersion(),
                observedVersion,
                workspace.toString(),
                expectedPlanSha256,
                observedPlanSha256,
                command.operation().name(),
                result.exitCode(),
                result.timedOut(),
                state,
                reasonCodes,
                result.stdoutSize(), result.stderrSize(), result.stdoutSha256(), result.stderrSha256(),
                startedAt, result.completedAt());
    }

    private static String parseTerraformVersion(byte[] stdout) {
        try {
            JsonNode root = MAPPER.readTree(stdout);
            JsonNode versionNode = root.path("terraform_version");
            return versionNode.isMissingNode() || versionNode.isNull() ? null : versionNode.asText();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static boolean isValidJson(byte[] content) {
        try {
            MAPPER.readTree(content);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static String sha256Hex(byte[] content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(content));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available on any supported JVM", e);
        }
    }

    private static String emptyHash() {
        return sha256Hex(new byte[0]);
    }
}
