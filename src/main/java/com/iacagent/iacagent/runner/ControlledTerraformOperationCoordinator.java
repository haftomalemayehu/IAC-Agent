package com.iacagent.iacagent.runner;

import com.iacagent.iacagent.PlanJsonParser;
import com.iacagent.iacagent.PlanSummary;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
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

    private static final long DEFAULT_LOCKFILE_MAX_BYTES = 5L * 1024 * 1024; // 5 MiB - a lockfile is a small, human-reviewable text file

    private final TerraformExecutableProvider executableProvider;
    private final TerraformCommandFactory commandFactory;
    private final ControlledTerraformProcess process;
    private final RunnerWorkspaceManager workspaceManager;
    private final Duration versionTimeout;
    private final Duration fmtCheckTimeout;
    private final Duration showPlanJsonTimeout;
    private final Duration initTimeout;
    private final Duration validateTimeout;
    private final Duration providersSchemaTimeout;
    private final TerraformSourcePolicy sourcePolicy;
    private final TerraformBackendMode backendMode;
    private final TrustedBackendResolver backendResolver;
    private final TerraformCredentialProvider credentialProvider;
    private final TerraformPlanArtifactStore planArtifactStore;
    private final Duration planInitTimeout;
    private final Duration planTimeout;

    private final Object attestationLock = new Object();
    private VerifiedTerraformExecutable cachedAttestation;

    /** Phase 2B-3 constructor - EXACT ORIGINAL SIGNATURE, unchanged, so every existing Phase 2B-3
     * test/call site keeps compiling and behaving identically. Defaults the Phase 2B-4 policy this
     * coordinator enforces to the restrictive baseline ({@link TerraformSourcePolicy#restrictiveDefault()},
     * {@link TerraformBackendMode#LOCAL_ONLY}), reuses {@code fmtCheckTimeout} for the three new
     * operations' timeouts, and leaves {@code workspaceManager} unset ({@code null}) - none of that
     * is ever observed by a caller built this way, since {@link #executeInit}/{@link #executeValidate}/
     * {@link #executeProvidersSchema} are new Phase 2B-4 entry points no Phase 2B-3 caller invokes.
     * Calling one of those three methods on a coordinator built via this constructor throws
     * {@link IllegalStateException} immediately - a wiring error, not a request-shaped outcome,
     * exactly like calling {@link ControlledRunner}'s Terraform methods with no coordinator at all
     * produces {@link RunnerReasonCode#TERRAFORM_OPERATION_NOT_ALLOWED} rather than an NPE. */
    ControlledTerraformOperationCoordinator(
            TerraformExecutableProvider executableProvider,
            TerraformCommandFactory commandFactory,
            ControlledTerraformProcess process,
            Duration versionTimeout,
            Duration fmtCheckTimeout,
            Duration showPlanJsonTimeout) {
        this(executableProvider, commandFactory, process, null, versionTimeout, fmtCheckTimeout, showPlanJsonTimeout,
                fmtCheckTimeout, fmtCheckTimeout, fmtCheckTimeout, TerraformSourcePolicy.restrictiveDefault(), TerraformBackendMode.LOCAL_ONLY);
    }

    /** Phase 2B-4 constructor - EXACT ORIGINAL SIGNATURE, unchanged, so every existing Phase 2B-4
     * test/call site keeps compiling and behaving identically. Leaves the Phase 2B-5
     * backend/credential/plan-artifact-store dependencies unset ({@code null}) - a coordinator built
     * this way throws {@link IllegalStateException} if {@link #executePlan} is ever called, exactly
     * like the 6-arg constructor's relationship to the Phase 2B-4 methods. */
    ControlledTerraformOperationCoordinator(
            TerraformExecutableProvider executableProvider,
            TerraformCommandFactory commandFactory,
            ControlledTerraformProcess process,
            RunnerWorkspaceManager workspaceManager,
            Duration versionTimeout,
            Duration fmtCheckTimeout,
            Duration showPlanJsonTimeout,
            Duration initTimeout,
            Duration validateTimeout,
            Duration providersSchemaTimeout,
            TerraformSourcePolicy sourcePolicy,
            TerraformBackendMode backendMode) {
        this(executableProvider, commandFactory, process, workspaceManager, versionTimeout, fmtCheckTimeout, showPlanJsonTimeout,
                initTimeout, validateTimeout, providersSchemaTimeout, sourcePolicy, backendMode,
                null, null, null, initTimeout, initTimeout);
    }

    /** Phase 2B-5 constructor. */
    ControlledTerraformOperationCoordinator(
            TerraformExecutableProvider executableProvider,
            TerraformCommandFactory commandFactory,
            ControlledTerraformProcess process,
            RunnerWorkspaceManager workspaceManager,
            Duration versionTimeout,
            Duration fmtCheckTimeout,
            Duration showPlanJsonTimeout,
            Duration initTimeout,
            Duration validateTimeout,
            Duration providersSchemaTimeout,
            TerraformSourcePolicy sourcePolicy,
            TerraformBackendMode backendMode,
            TrustedBackendResolver backendResolver,
            TerraformCredentialProvider credentialProvider,
            TerraformPlanArtifactStore planArtifactStore,
            Duration planInitTimeout,
            Duration planTimeout) {
        this.executableProvider = require(executableProvider, "executableProvider");
        this.commandFactory = require(commandFactory, "commandFactory");
        this.process = require(process, "process");
        this.workspaceManager = workspaceManager; // nullable - see the 6-arg (Phase 2B-3) constructor's javadoc
        this.versionTimeout = requirePositive(versionTimeout, "versionTimeout");
        this.fmtCheckTimeout = requirePositive(fmtCheckTimeout, "fmtCheckTimeout");
        this.showPlanJsonTimeout = requirePositive(showPlanJsonTimeout, "showPlanJsonTimeout");
        this.initTimeout = requirePositive(initTimeout, "initTimeout");
        this.validateTimeout = requirePositive(validateTimeout, "validateTimeout");
        this.providersSchemaTimeout = requirePositive(providersSchemaTimeout, "providersSchemaTimeout");
        this.sourcePolicy = require(sourcePolicy, "sourcePolicy");
        this.backendMode = require(backendMode, "backendMode");
        this.backendResolver = backendResolver; // nullable - see this constructor's Phase 2B-4 delegate javadoc
        this.credentialProvider = credentialProvider; // nullable
        this.planArtifactStore = planArtifactStore; // nullable
        this.planInitTimeout = requirePositive(planInitTimeout, "planInitTimeout");
        this.planTimeout = requirePositive(planTimeout, "planTimeout");
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

    // ===================== Phase 2B-4: TERRAFORM_INIT / TERRAFORM_VALIDATE / TERRAFORM_PROVIDERS_SCHEMA =====================

    /** Path-safety only for {@code .terraform.lock.hcl}: a symlink or non-regular-file at that path
     * is rejected outright, never read as a trusted lockfile - both {@code contentOrNull}/
     * {@code hashOrNull} are {@code null} when the path is genuinely absent (a legitimate, common
     * case) and when reading it failed for an unexpected I/O reason (treated conservatively as
     * {@code TERRAFORM_LOCKFILE_INVALID} by the caller, not silently as "absent"). {@code contentOrNull}
     * is carried (not just the hash) so the lockfile can also be folded into
     * {@link TerraformConfigIdentity}'s filename-bound hash as a {@code ".terraform.lock.hcl"} entry. */
    private record LockfileCheck(byte[] contentOrNull, String hashOrNull, RunnerReasonCode failureReason) {
        boolean isSafe() {
            return failureReason == null;
        }
    }

    private LockfileCheck checkLockfile(Path lockfilePath) {
        if (Files.isSymbolicLink(lockfilePath)) {
            return new LockfileCheck(null, null, RunnerReasonCode.TERRAFORM_LOCKFILE_INVALID);
        }
        if (!Files.exists(lockfilePath)) {
            return new LockfileCheck(null, null, null);
        }
        if (!Files.isRegularFile(lockfilePath)) {
            return new LockfileCheck(null, null, RunnerReasonCode.TERRAFORM_LOCKFILE_INVALID);
        }
        try {
            long size = Files.size(lockfilePath);
            if (size > DEFAULT_LOCKFILE_MAX_BYTES) {
                return new LockfileCheck(null, null, RunnerReasonCode.TERRAFORM_LOCKFILE_INVALID);
            }
            byte[] content = Files.readAllBytes(lockfilePath);
            return new LockfileCheck(content, sha256Hex(content), null);
        } catch (IOException e) {
            return new LockfileCheck(null, null, RunnerReasonCode.TERRAFORM_LOCKFILE_INVALID);
        }
    }

    /**
     * Runs the full Phase 2B-4 {@code init} sequence: lockfile pre-check (symlink/type defense) →
     * backend-mode check → configuration identity → source-policy validation (static scan, before
     * any process launch) → trusted-executable attestation → runner-owned CLI config preparation →
     * launch → lockfile post-check. Every pre-launch check that fails returns a {@code BLOCKED}
     * evidence record with the process never having been started at all.
     */
    TerraformInitEvidence executeInit(RunnerRequest request, RunnerIdentity identity, Path workspace, List<TerraformConfigIdentity.NamedConfigFile> configFiles) {
        if (workspaceManager == null) {
            throw new IllegalStateException("this coordinator was not constructed with a RunnerWorkspaceManager - TERRAFORM_INIT is unavailable");
        }
        Instant startedAt = Instant.now();
        Path lockfilePath = workspace.resolve(".terraform.lock.hcl");

        LockfileCheck before = checkLockfile(lockfilePath);
        if (!before.isSafe()) {
            return blockedInit(request, identity, before.failureReason(), null, null, null, null, List.of(), List.of(), null, startedAt);
        }
        if (backendMode != TerraformBackendMode.LOCAL_ONLY) {
            return blockedInit(request, identity, RunnerReasonCode.TERRAFORM_BACKEND_MODE_UNSAFE, null, null, null, null,
                    List.of(), List.of(), before.hashOrNull(), startedAt);
        }

        String configSha256 = TerraformConfigIdentity.computeSha256(withLockfileEntry(configFiles, before));

        TerraformConfigSourceManifest manifest;
        try {
            manifest = TerraformConfigSourceExtractor.extract(configFiles);
        } catch (TerraformConfigSourceExtractionException e) {
            return blockedInit(request, identity, RunnerReasonCode.TERRAFORM_SOURCE_EXTRACTION_FAILED, configSha256, null, null, null,
                    List.of(), List.of(), before.hashOrNull(), startedAt);
        }
        // Amendment: ANY module block blocks unconditionally, regardless of what TerraformSourcePolicy
        // would otherwise say about its source. A directly-allowlisted module source only proves the
        // DIRECT reference is trusted - this runner does not yet recursively stage/parse/policy-check
        // a module's own downloaded contents, so a module's transitive provider/module dependencies
        // could still exceed what this pre-init manifest describes. Module sources remain parsed and
        // canonicalized into evidence (moduleSources below) for the later phase that will implement a
        // real dependency-graph resolution - they are simply not execution-eligible yet. See
        // docs/phase-2b4-controlled-init-validation.md for the full reasoning; TERRAFORM_MODULE_SOURCE_UNTRUSTED
        // and TerraformSourcePolicy#isModuleSourceAllowed remain defined/tested for that future phase,
        // but are unreachable from this coordinator today since this check always runs first.
        if (!manifest.moduleSources().isEmpty()) {
            return blockedInit(request, identity, RunnerReasonCode.TERRAFORM_MODULE_DEPENDENCY_GRAPH_UNRESOLVED, configSha256, null, null, null,
                    manifest.providerSources(), manifest.moduleSources(), before.hashOrNull(), startedAt);
        }
        // Amendment: a provider Terraform could resolve IMPLICITLY (a resource/data block's type
        // prefix, or a bare `provider "x" {}` block) with no explicit required_providers entry must
        // still block - this runner never relies on Terraform's own implicit
        // registry.terraform.io/hashicorp/<name> fallback for a provider the staged configuration
        // itself never declared, since TerraformSourcePolicy can only ever evaluate sources it is
        // actually given.
        if (!manifest.undeclaredImpliedProviderLocalNames().isEmpty()) {
            return blockedInit(request, identity, RunnerReasonCode.TERRAFORM_PROVIDER_REQUIREMENT_IMPLICIT, configSha256, null, null, null,
                    manifest.providerSources(), manifest.moduleSources(), before.hashOrNull(), startedAt);
        }
        for (String providerSource : manifest.providerSources()) {
            if (!sourcePolicy.isProviderSourceAllowed(providerSource)) {
                return blockedInit(request, identity, RunnerReasonCode.TERRAFORM_PROVIDER_SOURCE_UNTRUSTED, configSha256, null, null, null,
                        manifest.providerSources(), manifest.moduleSources(), before.hashOrNull(), startedAt);
            }
        }
        TerraformNetworkRequirement networkRequirement =
                manifest.providerSources().isEmpty() ? TerraformNetworkRequirement.NONE : TerraformNetworkRequirement.PROVIDER_REGISTRY_ONLY;

        AttestationOutcome attestation = obtainVerifiedExecutable(request, workspace);
        if (!attestation.isVerified()) {
            return blockedInit(request, identity, attestation.failureReason(), configSha256, attestation.observedSha256(), attestation.observedVersion(),
                    networkRequirement, manifest.providerSources(), manifest.moduleSources(), before.hashOrNull(), startedAt);
        }

        workspaceManager.prepareTerraformCliConfig(workspace);

        ControlledTerraformCommand command = commandFactory.initCommand(request, attestation.descriptor(), workspace, initTimeout);
        TerraformProcessResult result = process.execute(command);
        return interpretInit(request, identity, attestation.descriptor(), attestation.observedSha256(), attestation.observedVersion(),
                configSha256, networkRequirement, manifest, before.hashOrNull(), lockfilePath, command, result, startedAt);
    }

    /** Folds the lockfile (when present) into the same list of {@link TerraformConfigIdentity.NamedConfigFile}
     * entries the staged {@code *.tf}/{@code *.tf.json} files already are, under the fixed relative
     * name {@code ".terraform.lock.hcl"} - see {@link TerraformConfigIdentity} for why the lockfile
     * must be part of the SAME filename-bound hash rather than a separate parameter. */
    private static List<TerraformConfigIdentity.NamedConfigFile> withLockfileEntry(
            List<TerraformConfigIdentity.NamedConfigFile> configFiles, LockfileCheck lockfile) {
        if (lockfile.contentOrNull() == null) {
            return configFiles;
        }
        List<TerraformConfigIdentity.NamedConfigFile> withLockfile = new ArrayList<>(configFiles);
        withLockfile.add(new TerraformConfigIdentity.NamedConfigFile(".terraform.lock.hcl", lockfile.contentOrNull()));
        return withLockfile;
    }

    private TerraformInitEvidence interpretInit(
            RunnerRequest request, RunnerIdentity identity, TerraformExecutableDescriptor descriptor, String observedExecutableSha256,
            String observedVersion, String configSha256, TerraformNetworkRequirement networkRequirement,
            TerraformConfigSourceManifest manifest, String lockfileHashBefore, Path lockfilePath,
            ControlledTerraformCommand command, TerraformProcessResult result, Instant startedAt) {
        if (result.timedOut()) {
            return terminalInit(request, identity, descriptor, observedExecutableSha256, observedVersion, configSha256, networkRequirement,
                    manifest, lockfileHashBefore, null, command, result, TerraformProcessState.TIMED_OUT,
                    List.of(RunnerReasonCode.TERRAFORM_PROCESS_TIMEOUT), startedAt);
        }
        if (result.outputLimitExceeded()) {
            return terminalInit(request, identity, descriptor, observedExecutableSha256, observedVersion, configSha256, networkRequirement,
                    manifest, lockfileHashBefore, null, command, result, TerraformProcessState.OUTPUT_LIMIT_EXCEEDED,
                    List.of(RunnerReasonCode.TERRAFORM_OUTPUT_LIMIT_EXCEEDED), startedAt);
        }
        if (result.startFailed()) {
            return terminalInit(request, identity, descriptor, observedExecutableSha256, observedVersion, configSha256, networkRequirement,
                    manifest, lockfileHashBefore, null, command, result, TerraformProcessState.BLOCKED,
                    List.of(RunnerReasonCode.TERRAFORM_PROCESS_START_FAILED), startedAt);
        }

        // Re-check the lockfile regardless of exit code - a failing init might still have written
        // (or corrupted) one, and -lockfile=readonly should mean it never legitimately changes.
        LockfileCheck after = checkLockfile(lockfilePath);
        List<RunnerReasonCode> lockfileReasons = new ArrayList<>();
        if (!after.isSafe()) {
            lockfileReasons.add(after.failureReason());
        } else if (lockfileHashBefore != null && !lockfileHashBefore.equals(after.hashOrNull())) {
            lockfileReasons.add(RunnerReasonCode.TERRAFORM_LOCKFILE_CHANGED);
        }

        if (result.exitCode() != 0) {
            List<RunnerReasonCode> reasons = new ArrayList<>(List.of(RunnerReasonCode.TERRAFORM_INIT_FAILED));
            reasons.addAll(lockfileReasons);
            return terminalInit(request, identity, descriptor, observedExecutableSha256, observedVersion, configSha256, networkRequirement,
                    manifest, lockfileHashBefore, after.hashOrNull(), command, result, TerraformProcessState.FAILED, reasons, startedAt);
        }
        if (!lockfileReasons.isEmpty()) {
            return terminalInit(request, identity, descriptor, observedExecutableSha256, observedVersion, configSha256, networkRequirement,
                    manifest, lockfileHashBefore, after.hashOrNull(), command, result, TerraformProcessState.FAILED, lockfileReasons, startedAt);
        }
        if (!manifest.providerSources().isEmpty() && after.hashOrNull() == null) {
            return terminalInit(request, identity, descriptor, observedExecutableSha256, observedVersion, configSha256, networkRequirement,
                    manifest, lockfileHashBefore, null, command, result, TerraformProcessState.FAILED,
                    List.of(RunnerReasonCode.TERRAFORM_LOCKFILE_MISSING), startedAt);
        }
        return terminalInit(request, identity, descriptor, observedExecutableSha256, observedVersion, configSha256, networkRequirement,
                manifest, lockfileHashBefore, after.hashOrNull(), command, result, TerraformProcessState.SUCCEEDED, List.of(), startedAt);
    }

    private TerraformInitEvidence blockedInit(
            RunnerRequest request, RunnerIdentity identity, RunnerReasonCode reason, String configSha256, String observedExecutableSha256,
            String observedVersion, TerraformNetworkRequirement networkRequirement, List<String> providerSources, List<String> moduleSources,
            String lockfileHashBefore, Instant startedAt) {
        Instant completedAt = Instant.now();
        return new TerraformInitEvidence(
                request.runnerRequestId(), identity == null ? null : identity.runnerId(), configSha256,
                null, observedExecutableSha256, null, observedVersion, backendMode,
                networkRequirement == null ? TerraformNetworkRequirement.NONE : networkRequirement,
                providerSources, moduleSources, lockfileHashBefore, null,
                0, false, TerraformProcessState.BLOCKED, List.of(reason),
                0, 0, emptyHash(), emptyHash(), startedAt, completedAt);
    }

    private TerraformInitEvidence terminalInit(
            RunnerRequest request, RunnerIdentity identity, TerraformExecutableDescriptor descriptor, String observedExecutableSha256,
            String observedVersion, String configSha256, TerraformNetworkRequirement networkRequirement,
            TerraformConfigSourceManifest manifest, String lockfileHashBefore, String lockfileHashAfter,
            ControlledTerraformCommand command, TerraformProcessResult result, TerraformProcessState state,
            List<RunnerReasonCode> reasonCodes, Instant startedAt) {
        return new TerraformInitEvidence(
                request.runnerRequestId(), identity == null ? null : identity.runnerId(), configSha256,
                descriptor.expectedSha256(), observedExecutableSha256, descriptor.expectedVersion(), observedVersion,
                backendMode, networkRequirement, manifest.providerSources(), manifest.moduleSources(),
                lockfileHashBefore, lockfileHashAfter,
                result.exitCode(), result.timedOut(), state, reasonCodes,
                result.stdoutSize(), result.stderrSize(), result.stdoutSha256(), result.stderrSha256(),
                startedAt, result.completedAt());
    }

    /**
     * Runs {@link #executeInit} against the identical staged configuration; only if that succeeds
     * does {@code terraform validate -json} ever launch. {@code initEvidence} is embedded in the
     * result either way, so "validate never ran without a successful, freshly-run init for the same
     * config identity" is a structural property of the returned record, not a side claim.
     */
    TerraformValidateEvidence executeValidate(RunnerRequest request, RunnerIdentity identity, Path workspace, List<TerraformConfigIdentity.NamedConfigFile> configFiles) {
        Instant startedAt = Instant.now();
        TerraformInitEvidence initEvidence = executeInit(request, identity, workspace, configFiles);
        if (!initEvidence.succeeded()) {
            return new TerraformValidateEvidence(
                    request.runnerRequestId(), identity == null ? null : identity.runnerId(), initEvidence, initEvidence.configSha256(),
                    null, null, null, List.of(), null, false, TerraformProcessState.BLOCKED,
                    List.of(RunnerReasonCode.TERRAFORM_INIT_REQUIRED), emptyHash(), startedAt, Instant.now());
        }
        AttestationOutcome attestation = obtainVerifiedExecutable(request, workspace);
        if (!attestation.isVerified()) {
            return new TerraformValidateEvidence(
                    request.runnerRequestId(), identity == null ? null : identity.runnerId(), initEvidence, initEvidence.configSha256(),
                    null, null, null, List.of(), null, false, TerraformProcessState.BLOCKED,
                    List.of(attestation.failureReason()), emptyHash(), startedAt, Instant.now());
        }
        ControlledTerraformCommand command = commandFactory.validateCommand(request, attestation.descriptor(), workspace, validateTimeout);
        TerraformProcessResult result = process.execute(command);
        return interpretValidate(request, identity, initEvidence, command, result, startedAt);
    }

    private TerraformValidateEvidence interpretValidate(
            RunnerRequest request, RunnerIdentity identity, TerraformInitEvidence initEvidence,
            ControlledTerraformCommand command, TerraformProcessResult result, Instant startedAt) {
        String runnerId = identity == null ? null : identity.runnerId();
        if (result.timedOut()) {
            return validateTerminal(request, runnerId, initEvidence, command, result, TerraformProcessState.TIMED_OUT,
                    List.of(RunnerReasonCode.TERRAFORM_PROCESS_TIMEOUT), null, null, null, List.of(), startedAt);
        }
        if (result.outputLimitExceeded()) {
            return validateTerminal(request, runnerId, initEvidence, command, result, TerraformProcessState.OUTPUT_LIMIT_EXCEEDED,
                    List.of(RunnerReasonCode.TERRAFORM_OUTPUT_LIMIT_EXCEEDED), null, null, null, List.of(), startedAt);
        }
        if (result.startFailed()) {
            return validateTerminal(request, runnerId, initEvidence, command, result, TerraformProcessState.BLOCKED,
                    List.of(RunnerReasonCode.TERRAFORM_PROCESS_START_FAILED), null, null, null, List.of(), startedAt);
        }
        JsonNode root;
        try {
            root = MAPPER.readTree(result.stdout());
        } catch (RuntimeException e) {
            return validateTerminal(request, runnerId, initEvidence, command, result, TerraformProcessState.FAILED,
                    List.of(RunnerReasonCode.TERRAFORM_VALIDATE_OUTPUT_INVALID), null, null, null, List.of(), startedAt);
        }
        JsonNode validNode = root.path("valid");
        if (validNode.isMissingNode() || !validNode.isBoolean()) {
            return validateTerminal(request, runnerId, initEvidence, command, result, TerraformProcessState.FAILED,
                    List.of(RunnerReasonCode.TERRAFORM_VALIDATE_OUTPUT_INVALID), null, null, null, List.of(), startedAt);
        }
        boolean valid = validNode.asBoolean();
        int errorCount = root.path("error_count").asInt(0);
        int warningCount = root.path("warning_count").asInt(0);
        List<String> fingerprints = new ArrayList<>();
        for (JsonNode diagnostic : root.path("diagnostics")) {
            String severity = diagnostic.path("severity").asText("");
            String summary = diagnostic.path("summary").asText("");
            String detail = diagnostic.path("detail").asText("");
            fingerprints.add(sha256Hex((severity + "|" + summary + "|" + detail).getBytes(StandardCharsets.UTF_8)));
        }
        if (result.exitCode() != 0 && valid) {
            // A nonzero exit alongside a structurally-valid, "valid": true document is not a
            // combination this operation trusts - real Terraform never produces it, so treat it as
            // untrustworthy output rather than reporting success.
            return validateTerminal(request, runnerId, initEvidence, command, result, TerraformProcessState.FAILED,
                    List.of(RunnerReasonCode.TERRAFORM_VALIDATE_OUTPUT_INVALID), null, null, null, List.of(), startedAt);
        }
        TerraformProcessState state = valid ? TerraformProcessState.SUCCEEDED : TerraformProcessState.COMMAND_REPORTED_DIFFERENCE;
        return validateTerminal(request, runnerId, initEvidence, command, result, state, List.of(), valid, errorCount, warningCount, fingerprints, startedAt);
    }

    private TerraformValidateEvidence validateTerminal(
            RunnerRequest request, String runnerId, TerraformInitEvidence initEvidence, ControlledTerraformCommand command,
            TerraformProcessResult result, TerraformProcessState state, List<RunnerReasonCode> reasonCodes,
            Boolean valid, Integer errorCount, Integer warningCount, List<String> diagnosticFingerprints, Instant startedAt) {
        return new TerraformValidateEvidence(
                request.runnerRequestId(), runnerId, initEvidence, initEvidence.configSha256(),
                valid, errorCount, warningCount, diagnosticFingerprints,
                result.exitCode(), result.timedOut(), state, reasonCodes, result.stdoutSha256(), startedAt, result.completedAt());
    }

    /**
     * Runs {@link #executeInit} against the identical staged configuration; only if that succeeds
     * does {@code terraform providers schema -json} ever launch. Binds {@code lockfileHash} to
     * whatever the init step recorded AFTER it ran - the exact lockfile state schema output was
     * actually produced under.
     */
    TerraformProviderSchemaEvidence executeProvidersSchema(RunnerRequest request, RunnerIdentity identity, Path workspace, List<TerraformConfigIdentity.NamedConfigFile> configFiles) {
        Instant startedAt = Instant.now();
        TerraformInitEvidence initEvidence = executeInit(request, identity, workspace, configFiles);
        String runnerId = identity == null ? null : identity.runnerId();
        if (!initEvidence.succeeded()) {
            return new TerraformProviderSchemaEvidence(
                    request.runnerRequestId(), runnerId, initEvidence, initEvidence.configSha256(), initEvidence.lockfileHashAfter(),
                    initEvidence.providerSourcesRequested(), emptyHash(), 0, initEvidence.terraformVersionObserved(),
                    null, false, TerraformProcessState.BLOCKED, List.of(RunnerReasonCode.TERRAFORM_INIT_REQUIRED), startedAt, Instant.now());
        }
        AttestationOutcome attestation = obtainVerifiedExecutable(request, workspace);
        if (!attestation.isVerified()) {
            return new TerraformProviderSchemaEvidence(
                    request.runnerRequestId(), runnerId, initEvidence, initEvidence.configSha256(), initEvidence.lockfileHashAfter(),
                    initEvidence.providerSourcesRequested(), emptyHash(), 0, initEvidence.terraformVersionObserved(),
                    null, false, TerraformProcessState.BLOCKED, List.of(attestation.failureReason()), startedAt, Instant.now());
        }
        ControlledTerraformCommand command = commandFactory.providersSchemaCommand(request, attestation.descriptor(), workspace, providersSchemaTimeout);
        TerraformProcessResult result = process.execute(command);
        return interpretProvidersSchema(request, runnerId, initEvidence, command, result, startedAt);
    }

    private TerraformProviderSchemaEvidence interpretProvidersSchema(
            RunnerRequest request, String runnerId, TerraformInitEvidence initEvidence,
            ControlledTerraformCommand command, TerraformProcessResult result, Instant startedAt) {
        if (result.timedOut()) {
            return schemaTerminal(request, runnerId, initEvidence, command, result, TerraformProcessState.TIMED_OUT,
                    List.of(RunnerReasonCode.TERRAFORM_PROCESS_TIMEOUT), List.of(), startedAt);
        }
        if (result.outputLimitExceeded()) {
            return schemaTerminal(request, runnerId, initEvidence, command, result, TerraformProcessState.OUTPUT_LIMIT_EXCEEDED,
                    List.of(RunnerReasonCode.TERRAFORM_OUTPUT_LIMIT_EXCEEDED), List.of(), startedAt);
        }
        if (result.startFailed()) {
            return schemaTerminal(request, runnerId, initEvidence, command, result, TerraformProcessState.BLOCKED,
                    List.of(RunnerReasonCode.TERRAFORM_PROCESS_START_FAILED), List.of(), startedAt);
        }
        if (result.exitCode() != 0) {
            return schemaTerminal(request, runnerId, initEvidence, command, result, TerraformProcessState.FAILED,
                    List.of(RunnerReasonCode.TERRAFORM_PROVIDER_SCHEMA_FAILED), List.of(), startedAt);
        }
        JsonNode root;
        try {
            root = MAPPER.readTree(result.stdout());
        } catch (RuntimeException e) {
            return schemaTerminal(request, runnerId, initEvidence, command, result, TerraformProcessState.FAILED,
                    List.of(RunnerReasonCode.TERRAFORM_PROVIDER_SCHEMA_OUTPUT_INVALID), List.of(), startedAt);
        }
        JsonNode providerSchemas = root.path("provider_schemas");
        List<String> providerIdentities = new ArrayList<>();
        if (providerSchemas.isObject()) {
            providerIdentities.addAll(providerSchemas.propertyNames());
        }
        return schemaTerminal(request, runnerId, initEvidence, command, result, TerraformProcessState.SUCCEEDED, List.of(), providerIdentities, startedAt);
    }

    private TerraformProviderSchemaEvidence schemaTerminal(
            RunnerRequest request, String runnerId, TerraformInitEvidence initEvidence, ControlledTerraformCommand command,
            TerraformProcessResult result, TerraformProcessState state, List<RunnerReasonCode> reasonCodes,
            List<String> providerIdentities, Instant startedAt) {
        return new TerraformProviderSchemaEvidence(
                request.runnerRequestId(), runnerId, initEvidence, initEvidence.configSha256(), initEvidence.lockfileHashAfter(),
                providerIdentities.isEmpty() ? initEvidence.providerSourcesRequested() : providerIdentities,
                result.stdoutSha256(), result.stdoutSize(), initEvidence.terraformVersionObserved(),
                result.exitCode(), result.timedOut(), state, reasonCodes, startedAt, result.completedAt());
    }

    // ===================== Phase 2B-5: TERRAFORM_PLAN =====================

    /**
     * Produces a real, saved Terraform plan artifact against a trusted, control-plane-resolved
     * backend/state target. Sequencing: lockfile pre-check → config identity → source-policy gates
     * (backend-block / module-presence / implicit-provider / provider-source, all reused unchanged
     * from {@link #executeInit}) → trusted backend resolution → credentials → executable attestation
     * → runner-owned backend file + CLI config → controlled {@code init} against the REAL backend →
     * plan input identity → {@code terraform plan -out=...} → saved-plan validation/hashing →
     * TOCTOU rehash → {@code terraform show -json} on the exact hashed bytes → durable artifact
     * storage. Every pre-launch check that fails returns a {@code BLOCKED} evidence record with no
     * process ever started.
     */
    TerraformPlanEvidence executePlan(RunnerRequest request, RunnerIdentity identity, Path workspace, List<TerraformConfigIdentity.NamedConfigFile> configFiles) {
        if (workspaceManager == null || backendResolver == null || credentialProvider == null || planArtifactStore == null) {
            throw new IllegalStateException("this coordinator was not constructed with backend/credential/plan-artifact-store dependencies - TERRAFORM_PLAN is unavailable");
        }
        Instant startedAt = Instant.now();
        String runnerId = identity == null ? null : identity.runnerId();

        Path lockfilePath = workspace.resolve(".terraform.lock.hcl");
        LockfileCheck before = checkLockfile(lockfilePath);
        if (!before.isSafe()) {
            return blockedPlan(request, runnerId, before.failureReason(), null, null, null, null, null, null, startedAt);
        }

        String configSha256 = TerraformConfigIdentity.computeSha256(withLockfileEntry(configFiles, before));

        TerraformConfigSourceManifest manifest;
        try {
            manifest = TerraformConfigSourceExtractor.extract(configFiles);
        } catch (TerraformConfigSourceExtractionException e) {
            return blockedPlan(request, runnerId, RunnerReasonCode.TERRAFORM_SOURCE_EXTRACTION_FAILED, configSha256, null, null, null, null, null, startedAt);
        }
        if (manifest.declaresBackendBlock()) {
            return blockedPlan(request, runnerId, RunnerReasonCode.TERRAFORM_BACKEND_BLOCK_NOT_ALLOWED, configSha256, null, null, null, null, null, startedAt);
        }
        if (manifest.declaresRemoteStateDataSource()) {
            return blockedPlan(request, runnerId, RunnerReasonCode.TERRAFORM_REMOTE_STATE_DATA_SOURCE_NOT_ALLOWED, configSha256, null, null, null, null, null, startedAt);
        }
        if (!manifest.moduleSources().isEmpty()) {
            return blockedPlan(request, runnerId, RunnerReasonCode.TERRAFORM_MODULE_DEPENDENCY_GRAPH_UNRESOLVED, configSha256, null, null, null, null, null, startedAt);
        }
        if (!manifest.undeclaredImpliedProviderLocalNames().isEmpty()) {
            return blockedPlan(request, runnerId, RunnerReasonCode.TERRAFORM_PROVIDER_REQUIREMENT_IMPLICIT, configSha256, null, null, null, null, null, startedAt);
        }
        for (String providerSource : manifest.providerSources()) {
            if (!sourcePolicy.isProviderSourceAllowed(providerSource)) {
                return blockedPlan(request, runnerId, RunnerReasonCode.TERRAFORM_PROVIDER_SOURCE_UNTRUSTED, configSha256, null, null, null, null, null, startedAt);
            }
        }

        TerraformBackendResolution backend;
        try {
            backend = backendResolver.resolve(request.repository(), request.environment());
        } catch (RuntimeException e) {
            return blockedPlan(request, runnerId, RunnerReasonCode.TERRAFORM_STATE_BACKEND_UNAVAILABLE, configSha256, null, null, null, null, null, startedAt);
        }
        String stateIdentitySha256 = backend.stateIdentity().sha256Hex();

        TerraformCredentialMaterial credentials;
        try {
            credentials = credentialProvider.obtain(request, backend.stateIdentity());
        } catch (RuntimeException e) {
            return blockedPlan(request, runnerId, RunnerReasonCode.TERRAFORM_STATE_BACKEND_UNAVAILABLE, configSha256, stateIdentitySha256, null, backend, null, null, startedAt);
        }

        AttestationOutcome attestation = obtainVerifiedExecutable(request, workspace);
        if (!attestation.isVerified()) {
            return blockedPlan(request, runnerId, attestation.failureReason(), configSha256, stateIdentitySha256,
                    attestation.observedVersion(), backend, credentials.sourceIdentifier(), attestation.observedSha256(), startedAt);
        }

        try {
            workspaceManager.writeTrustedLocalBackendFile(workspace, backend.localStatePath());
            workspaceManager.prepareTerraformCliConfig(workspace);
        } catch (RuntimeException e) {
            return blockedPlan(request, runnerId, RunnerReasonCode.TERRAFORM_STATE_BACKEND_UNAVAILABLE, configSha256, stateIdentitySha256,
                    attestation.descriptor().expectedVersion(), backend, credentials.sourceIdentifier(), attestation.observedSha256(), startedAt);
        }

        ControlledTerraformCommand initCommand = commandFactory.initForPlanCommand(
                request, attestation.descriptor(), workspace, planInitTimeout, credentials.environmentVariables());
        TerraformProcessResult initResult = process.execute(initCommand);
        RunnerReasonCode initFailureReason = classifyNonPlanFailure(initResult, RunnerReasonCode.TERRAFORM_PLAN_INIT_FAILED);
        if (initFailureReason != null) {
            return blockedPlan(request, runnerId, initFailureReason, configSha256, stateIdentitySha256,
                    attestation.observedVersion(), backend, credentials.sourceIdentifier(), attestation.observedSha256(), startedAt);
        }

        String planInputSha256 = TerraformPlanInputIdentity.computeSha256(
                configSha256, stateIdentitySha256, request.providerLockHash(),
                attestation.descriptor().expectedSha256(), attestation.descriptor().expectedVersion(),
                request.environment(), "PLAN_LOCAL_BACKEND_REFERENCE", List.of());

        Path planPath;
        try {
            planPath = workspaceManager.preparePlanArtifactPath(workspace);
        } catch (RuntimeException e) {
            return blockedPlan(request, runnerId, RunnerReasonCode.TERRAFORM_PLAN_ARTIFACT_INVALID, configSha256, stateIdentitySha256,
                    attestation.observedVersion(), backend, credentials.sourceIdentifier(), attestation.observedSha256(), startedAt);
        }

        ControlledTerraformCommand planCommand = commandFactory.planCommand(
                request, attestation.descriptor(), workspace, planPath, planTimeout, credentials.environmentVariables());
        TerraformProcessResult planResult = process.execute(planCommand);

        return interpretPlan(request, runnerId, workspace, configSha256, stateIdentitySha256, planInputSha256, attestation.descriptor(),
                attestation.observedSha256(), attestation.observedVersion(), backend, credentials.sourceIdentifier(), planPath, planResult, startedAt);
    }

    /** {@code null} if the process succeeded (exit 0); otherwise the reason code for its failure -
     * timeout/output-limit/start-failed reuse the same reason codes every other operation in this
     * coordinator uses; a genuine nonzero-exit failure is first offered to {@link #classifyStderrFailure}
     * for a more specific sanitized classification (lock contention/timeout, backend unavailable)
     * before falling back to {@code genericFailureReason}. */
    private RunnerReasonCode classifyNonPlanFailure(TerraformProcessResult result, RunnerReasonCode genericFailureReason) {
        if (result.timedOut()) {
            return RunnerReasonCode.TERRAFORM_PROCESS_TIMEOUT;
        }
        if (result.outputLimitExceeded()) {
            return RunnerReasonCode.TERRAFORM_OUTPUT_LIMIT_EXCEEDED;
        }
        if (result.startFailed()) {
            return RunnerReasonCode.TERRAFORM_PROCESS_START_FAILED;
        }
        if (result.exitCode() != 0) {
            RunnerReasonCode classified = classifyStderrFailure(result.stderr());
            return classified != null ? classified : genericFailureReason;
        }
        return null;
    }

    /**
     * Transient, sanitized classification of a failed init-for-plan/plan process's BOUNDED stderr
     * into one of a small, deterministic set of reason codes - a Phase 2B-5 security-amendment
     * capability, explicitly permitted by the authorization ("the process layer can transiently
     * inspect bounded output and emit a sanitized classification"). The raw bytes examined here are
     * never returned, logged, or embedded in an exception message by this method or any caller -
     * only the resulting {@link RunnerReasonCode} (or {@code null}) ever escapes it. No LLM or
     * heuristic scoring is involved: this is a fixed, deterministic, case-insensitive substring
     * check against a small set of known Terraform diagnostic phrasings.
     *
     * <p>Epistemic humility (explicit requirement): Terraform's "lock already held" and "lock
     * acquisition timed out" failures share the same "Error acquiring the state lock" / "state
     * lock" banner text; only the timeout case additionally emits timeout-specific wording (the
     * local-backend/generic state-locking retry path's "timeout while attempting to acquire state
     * lock" message, surfaced because {@link TerraformCommandFactory}'s fixed, internally-controlled
     * {@code -lock-timeout} bound - never derived from the request - gives a genuine timeout window
     * to observe). When stderr mentions a state lock but does NOT contain that timeout-specific
     * wording, this method returns the less specific {@link RunnerReasonCode#TERRAFORM_STATE_LOCK_FAILED}
     * rather than guessing - it never fabricates a distinction the text does not actually support.
     * Similarly, a backend failure is classified as {@link RunnerReasonCode#TERRAFORM_STATE_BACKEND_UNAVAILABLE}
     * only when stderr mentions both "backend" and clear failure/configuration-error wording;
     * anything less specific falls through to {@code null} (the caller's generic
     * {@code TERRAFORM_PLAN_INIT_FAILED}/{@code TERRAFORM_PLAN_FAILED}).
     */
    private static RunnerReasonCode classifyStderrFailure(byte[] stderr) {
        if (stderr == null || stderr.length == 0) {
            return null;
        }
        String text = new String(stderr, StandardCharsets.UTF_8).toLowerCase(java.util.Locale.ROOT);
        if (text.contains("state lock")) {
            return text.contains("timeout")
                    ? RunnerReasonCode.TERRAFORM_STATE_LOCK_TIMEOUT
                    : RunnerReasonCode.TERRAFORM_STATE_LOCK_FAILED;
        }
        boolean mentionsBackend = text.contains("backend");
        boolean mentionsUnavailability = text.contains("error configuring") || text.contains("failed to") || text.contains("could not");
        if (mentionsBackend && mentionsUnavailability) {
            return RunnerReasonCode.TERRAFORM_STATE_BACKEND_UNAVAILABLE;
        }
        return null;
    }

    private TerraformPlanEvidence interpretPlan(
            RunnerRequest request, String runnerId, Path workspace, String configSha256, String stateIdentitySha256, String planInputSha256,
            TerraformExecutableDescriptor descriptor, String executableSha256Observed, String terraformVersionObserved,
            TerraformBackendResolution backend, String credentialSourceIdentifier, Path planPath,
            TerraformProcessResult result, Instant startedAt) {
        if (result.timedOut()) {
            return planEvidence(request, runnerId, configSha256, stateIdentitySha256, planInputSha256, descriptor, executableSha256Observed,
                    terraformVersionObserved, request.providerLockHash(), backend, credentialSourceIdentifier, null, null, 0, null,
                    result.exitCode(), result.timedOut(), TerraformProcessState.TIMED_OUT, List.of(RunnerReasonCode.TERRAFORM_PROCESS_TIMEOUT),
                    startedAt, result.completedAt());
        }
        if (result.outputLimitExceeded()) {
            return planEvidence(request, runnerId, configSha256, stateIdentitySha256, planInputSha256, descriptor, executableSha256Observed,
                    terraformVersionObserved, request.providerLockHash(), backend, credentialSourceIdentifier, null, null, 0, null,
                    result.exitCode(), result.timedOut(), TerraformProcessState.OUTPUT_LIMIT_EXCEEDED, List.of(RunnerReasonCode.TERRAFORM_OUTPUT_LIMIT_EXCEEDED),
                    startedAt, result.completedAt());
        }
        if (result.startFailed()) {
            return planEvidence(request, runnerId, configSha256, stateIdentitySha256, planInputSha256, descriptor, executableSha256Observed,
                    terraformVersionObserved, request.providerLockHash(), backend, credentialSourceIdentifier, null, null, 0, null,
                    result.exitCode(), result.timedOut(), TerraformProcessState.BLOCKED, List.of(RunnerReasonCode.TERRAFORM_PROCESS_START_FAILED),
                    startedAt, result.completedAt());
        }
        // terraform plan -detailed-exitcode: 0 = success/no changes, 2 = success/changes present,
        // 1 (or anything else) = a genuine error. Exit code 2 is never treated as a failure.
        int exitCode = result.exitCode();
        if (exitCode != 0 && exitCode != 2) {
            RunnerReasonCode classified = classifyStderrFailure(result.stderr());
            RunnerReasonCode reason = classified != null ? classified : RunnerReasonCode.TERRAFORM_PLAN_FAILED;
            return planEvidence(request, runnerId, configSha256, stateIdentitySha256, planInputSha256, descriptor, executableSha256Observed,
                    terraformVersionObserved, request.providerLockHash(), backend, credentialSourceIdentifier, null, null, 0, null,
                    result.exitCode(), false, TerraformProcessState.FAILED, List.of(reason),
                    startedAt, result.completedAt());
        }
        TerraformProcessState state = exitCode == 0 ? TerraformProcessState.SUCCEEDED : TerraformProcessState.COMMAND_REPORTED_DIFFERENCE;

        Path validatedPlanPath;
        byte[] planBytes;
        try {
            validatedPlanPath = workspaceManager.validateSavedPlanArtifact(planPath);
            planBytes = Files.readAllBytes(validatedPlanPath);
        } catch (RuntimeException | IOException e) {
            return planEvidence(request, runnerId, configSha256, stateIdentitySha256, planInputSha256, descriptor, executableSha256Observed,
                    terraformVersionObserved, request.providerLockHash(), backend, credentialSourceIdentifier, null, null, 0, null,
                    result.exitCode(), false, TerraformProcessState.FAILED, List.of(RunnerReasonCode.TERRAFORM_PLAN_ARTIFACT_INVALID),
                    startedAt, result.completedAt());
        }
        String planSha256 = sha256Hex(planBytes);

        // TOCTOU: recompute the hash from a fresh read immediately before SHOW ever launches.
        byte[] recheckBytes;
        try {
            recheckBytes = Files.readAllBytes(validatedPlanPath);
        } catch (IOException e) {
            return planEvidence(request, runnerId, configSha256, stateIdentitySha256, planInputSha256, descriptor, executableSha256Observed,
                    terraformVersionObserved, request.providerLockHash(), backend, credentialSourceIdentifier, null, null, 0, null,
                    result.exitCode(), false, TerraformProcessState.FAILED, List.of(RunnerReasonCode.TERRAFORM_PLAN_HASH_MISMATCH),
                    startedAt, result.completedAt());
        }
        if (!planSha256.equals(sha256Hex(recheckBytes))) {
            return planEvidence(request, runnerId, configSha256, stateIdentitySha256, planInputSha256, descriptor, executableSha256Observed,
                    terraformVersionObserved, request.providerLockHash(), backend, credentialSourceIdentifier, null, null, 0, null,
                    result.exitCode(), false, TerraformProcessState.FAILED, List.of(RunnerReasonCode.TERRAFORM_PLAN_HASH_MISMATCH),
                    startedAt, result.completedAt());
        }

        ControlledTerraformCommand showCommand = commandFactory.showPlanJsonCommand(request, descriptor, workspace, validatedPlanPath, showPlanJsonTimeout);
        TerraformProcessResult showResult = process.execute(showCommand);
        if (showResult.timedOut() || showResult.outputLimitExceeded() || showResult.startFailed() || showResult.exitCode() != 0
                || !isValidJson(showResult.stdout())) {
            RunnerReasonCode reason = showResult.timedOut() ? RunnerReasonCode.TERRAFORM_PROCESS_TIMEOUT
                    : showResult.outputLimitExceeded() ? RunnerReasonCode.TERRAFORM_OUTPUT_LIMIT_EXCEEDED
                    : showResult.startFailed() ? RunnerReasonCode.TERRAFORM_PROCESS_START_FAILED
                    : !isValidJson(showResult.stdout()) ? RunnerReasonCode.TERRAFORM_OUTPUT_INVALID_JSON
                    : RunnerReasonCode.TERRAFORM_PROCESS_EXIT_FAILED;
            return planEvidence(request, runnerId, configSha256, stateIdentitySha256, planInputSha256, descriptor, executableSha256Observed,
                    terraformVersionObserved, request.providerLockHash(), backend, credentialSourceIdentifier, null,
                    showResult.stdoutSha256(), showResult.stdoutSize(), null,
                    result.exitCode(), false, TerraformProcessState.FAILED, List.of(reason), startedAt, showResult.completedAt());
        }

        PlanSummary summary;
        try {
            summary = new PlanJsonParser().parse(new String(showResult.stdout(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            return planEvidence(request, runnerId, configSha256, stateIdentitySha256, planInputSha256, descriptor, executableSha256Observed,
                    terraformVersionObserved, request.providerLockHash(), backend, credentialSourceIdentifier, null,
                    showResult.stdoutSha256(), showResult.stdoutSize(), null,
                    result.exitCode(), false, TerraformProcessState.FAILED, List.of(RunnerReasonCode.TERRAFORM_OUTPUT_INVALID_JSON),
                    startedAt, showResult.completedAt());
        }

        TerraformPlanArtifactMetadata artifactMetadata;
        try {
            artifactMetadata = planArtifactStore.store(
                    request.repository(), request.commitSha(), request.environment(), stateIdentitySha256, planInputSha256, planBytes);
        } catch (RuntimeException e) {
            // A hardening validation failure inside the durable store (e.g. an unsafe on-disk state
            // it refuses to write through) must fail closed as structured evidence, never propagate
            // as an uncaught exception through executePlan/ControlledRunner#execute. Never include
            // plan bytes or e's message (which could echo path/content details) in evidence.
            return planEvidence(request, runnerId, configSha256, stateIdentitySha256, planInputSha256, descriptor, executableSha256Observed,
                    terraformVersionObserved, request.providerLockHash(), backend, credentialSourceIdentifier, null,
                    showResult.stdoutSha256(), showResult.stdoutSize(), null,
                    result.exitCode(), false, TerraformProcessState.FAILED, List.of(RunnerReasonCode.TERRAFORM_PLAN_ARTIFACT_INVALID),
                    startedAt, showResult.completedAt());
        }

        return planEvidence(request, runnerId, configSha256, stateIdentitySha256, planInputSha256, descriptor, executableSha256Observed,
                terraformVersionObserved, request.providerLockHash(), backend, credentialSourceIdentifier, artifactMetadata,
                showResult.stdoutSha256(), showResult.stdoutSize(), summary,
                result.exitCode(), false, state, List.of(), startedAt, showResult.completedAt());
    }

    private TerraformPlanEvidence blockedPlan(
            RunnerRequest request, String runnerId, RunnerReasonCode reason, String configSha256, String stateIdentitySha256,
            String terraformVersionObserved, TerraformBackendResolution backend, String credentialSourceIdentifier,
            String executableSha256Observed, Instant startedAt) {
        Instant completedAt = Instant.now();
        return planEvidence(request, runnerId, configSha256, stateIdentitySha256, null, null, executableSha256Observed,
                terraformVersionObserved, request.providerLockHash(), backend, credentialSourceIdentifier, null, null, 0, null,
                0, false, TerraformProcessState.BLOCKED, List.of(reason), startedAt, completedAt);
    }

    private TerraformPlanEvidence planEvidence(
            RunnerRequest request, String runnerId, String configSha256, String stateIdentitySha256, String planInputSha256,
            TerraformExecutableDescriptor descriptor, String executableSha256Observed, String terraformVersionObserved,
            String providerLockHash, TerraformBackendResolution backend, String credentialSourceIdentifier,
            TerraformPlanArtifactMetadata artifactMetadata, String showJsonSha256, long showJsonByteSize, PlanSummary summary,
            Integer exitCode, boolean timedOut, TerraformProcessState state, List<RunnerReasonCode> reasonCodes,
            Instant startedAt, Instant completedAt) {
        return new TerraformPlanEvidence(
                request.runnerRequestId(), runnerId, request.repository(), request.commitSha(), request.environment(),
                configSha256, stateIdentitySha256, planInputSha256,
                descriptor == null ? null : descriptor.expectedSha256(), executableSha256Observed,
                descriptor == null ? null : descriptor.expectedVersion(), terraformVersionObserved,
                providerLockHash,
                backend == null ? null : backend.stateIdentity().backendType(),
                backend == null ? null : backend.stateIdentity().canonicalBackendInstanceId(),
                credentialSourceIdentifier,
                artifactMetadata == null ? null : artifactMetadata.planArtifactId(),
                artifactMetadata == null ? null : artifactMetadata.planSha256(),
                artifactMetadata == null ? 0 : artifactMetadata.planByteSize(),
                showJsonSha256, showJsonByteSize,
                summary == null ? null : summary.create(), summary == null ? null : summary.update(),
                summary == null ? null : summary.replace(), summary == null ? null : summary.destroy(),
                exitCode, timedOut, state, reasonCodes, startedAt, completedAt);
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
