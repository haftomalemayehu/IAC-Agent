package com.iacagent.iacagent.runner;

import com.iacagent.iacagent.approval.ApprovalPersistenceException;
import com.iacagent.iacagent.approval.ApprovalProvider;
import com.iacagent.iacagent.approval.ApprovalValidationReasonCode;
import com.iacagent.iacagent.approval.ApprovalValidationResult;
import com.iacagent.iacagent.approval.ApprovalValidator;
import com.iacagent.iacagent.approval.ExecutionIdentity;

import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Phase 2B controlled runner boundary. Exposes exactly one entry point,
 * {@link #execute(RunnerRequest)}, taking a fully typed {@link RunnerRequest} with a closed
 * {@link RunnerOperation}. There is no {@code execute(String command)}, no shell/process
 * invocation, and no operation value that represents infrastructure mutation anywhere in this
 * class or this package - no type in this package spawns an external process at all, and that is
 * a design property to preserve (see {@code Phase2b2Tests#runnerPackageContainsNoProcessInvocation}),
 * not an incidental fact about this commit.
 *
 * <p>Per the architecture discipline recorded in the Phase 2B-2 design doc, this class orchestrates
 * five independent sources of truth and manufactures none of them itself:
 * <ul>
 *   <li>{@link ApprovalProvider} - approval truth (read-only; never {@code ApprovalAuthority})
 *   <li>{@link RunnerIdentityProvider} - runner identity truth (never the request)
 *   <li>{@link RunnerArtifactStore} - artifact resolution truth (independently re-hashed)
 *   <li>{@link RunnerLedgerRepository} - request-consumption/evidence truth (durable; replaces
 *       Phase 2B-1's process-local maps)
 *   <li>{@link RunnerToolchainContext} - runner-observed toolchain truth
 * </ul>
 */
public final class ControlledRunner {

    private final RunnerIdentityProvider identityProvider;
    private final Set<String> allowedRunnerClasses;
    private final ApprovalProvider approvalProvider;
    private final RunnerArtifactStore artifactStore;
    private final RunnerToolchainContext toolchainContext;
    private final RunnerWorkspaceManager workspaceManager;
    private final RunnerLedgerRepository ledger;
    private final Clock clock;
    private final ControlledTerraformOperationCoordinator terraformCoordinator;

    /** Pre-Phase-2B-3 constructor - no Terraform process capability at all. A request for
     * {@code TERRAFORM_VERSION}/{@code TERRAFORM_FMT_CHECK}/{@code TERRAFORM_SHOW_PLAN_JSON}
     * against a runner built this way is BLOCKED / {@code TERRAFORM_OPERATION_NOT_ALLOWED}, never
     * an NPE - a runner not wired for Terraform simply does not support asking for it. */
    public ControlledRunner(
            RunnerIdentityProvider identityProvider,
            Set<String> allowedRunnerClasses,
            ApprovalProvider approvalProvider,
            RunnerArtifactStore artifactStore,
            RunnerToolchainContext toolchainContext,
            RunnerWorkspaceManager workspaceManager,
            RunnerLedgerRepository ledger,
            Clock clock
    ) {
        this(identityProvider, allowedRunnerClasses, approvalProvider, artifactStore, toolchainContext, workspaceManager, ledger, clock, null);
    }

    /** Phase 2B-3: {@code terraformCoordinator} may be null (same behavior as the shorter
     * constructor above) - it is never a required dependency of the identity/approval/artifact
     * pipeline the other seven parameters govern. */
    public ControlledRunner(
            RunnerIdentityProvider identityProvider,
            Set<String> allowedRunnerClasses,
            ApprovalProvider approvalProvider,
            RunnerArtifactStore artifactStore,
            RunnerToolchainContext toolchainContext,
            RunnerWorkspaceManager workspaceManager,
            RunnerLedgerRepository ledger,
            Clock clock,
            ControlledTerraformOperationCoordinator terraformCoordinator
    ) {
        this.identityProvider = require(identityProvider, "identityProvider");
        this.allowedRunnerClasses = allowedRunnerClasses == null ? Set.of() : Set.copyOf(allowedRunnerClasses);
        this.approvalProvider = require(approvalProvider, "approvalProvider");
        this.artifactStore = require(artifactStore, "artifactStore");
        this.toolchainContext = require(toolchainContext, "toolchainContext");
        this.workspaceManager = require(workspaceManager, "workspaceManager");
        this.ledger = require(ledger, "ledger");
        this.clock = require(clock, "clock");
        this.terraformCoordinator = terraformCoordinator;
    }

    /** Operations whose resolved artifact represents Terraform configuration content (staged as a
     * {@code .tf} file) rather than a saved plan (staged as {@code .tfplan}) - Phase 2B-4's three
     * new operations reuse the exact same single-artifact resolution/staging path
     * {@code TERRAFORM_FMT_CHECK} already established in Phase 2B-3, rather than introducing a
     * separate repository-checkout-root concept (see {@code docs/phase-2b4-controlled-init-validation.md}
     * for why that reuse, not {@link RunnerWorkspaceManager#stageTerraformConfigDirectory}, is this
     * phase's actual configuration staging model). */
    private static boolean isTerraformConfigOperation(RunnerOperation operation) {
        return operation == RunnerOperation.TERRAFORM_FMT_CHECK
                || operation == RunnerOperation.TERRAFORM_INIT
                || operation == RunnerOperation.TERRAFORM_VALIDATE
                || operation == RunnerOperation.TERRAFORM_PROVIDERS_SCHEMA
                || operation == RunnerOperation.TERRAFORM_PLAN;
    }

    private static <T> T require(T value, String name) {
        if (value == null) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }

    /**
     * Idempotency policy: block, never replay - unchanged from Phase 2B-1's accepted design, now
     * backed by the durable {@link RunnerLedgerRepository} instead of a process-local map, so it
     * survives restart:
     *
     * <pre>
     * first submission of a runnerRequestId          -&gt; processed normally
     * same id, byte-for-byte identical request again -&gt; BLOCKED / DUPLICATE_RUNNER_REQUEST
     * same id, DIFFERENT request content              -&gt; BLOCKED / RUNNER_REQUEST_FINGERPRINT_MISMATCH
     * same id, a prior claim never reached terminal    -&gt; BLOCKED / RUNNER_REQUEST_INCOMPLETE
     * </pre>
     *
     * A prior {@link RunnerEvidence} - even one that reached
     * {@link RunnerState#READY_FOR_FUTURE_EXECUTION} - is historical evidence, never a current
     * authorization: approval validity is time-varying and externally revocable, so an approval
     * that was ACTIVE at the time of the original submission may be REVOKED, SUPERSEDED, or expired
     * by the time of a resubmission. The original evidence remains available for audit via
     * {@link #historicalEvidence(String)}, clearly separated from "the result of this call."
     *
     * <p>If the durable ledger itself is unavailable, this call is BLOCKED /
     * {@code RUNNER_LEDGER_UNAVAILABLE} - never silently allowed to proceed without replay
     * protection, and never a signal to fall back to any in-memory tracking.
     */
    public RunnerEvidence execute(RunnerRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request is required");
        }
        Instant startedAt = clock.instant();

        RunnerClaimOutcome claimOutcome;
        try {
            claimOutcome = ledger.claim(request, startedAt);
        } catch (RunnerLedgerPersistenceException e) {
            return evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED,
                    List.of(RunnerReasonCode.RUNNER_LEDGER_UNAVAILABLE), null, null, null, null, null);
        }

        if (claimOutcome != RunnerClaimOutcome.CLAIMED) {
            RunnerReasonCode reason = switch (claimOutcome) {
                case DUPLICATE_SAME_FINGERPRINT -> RunnerReasonCode.DUPLICATE_RUNNER_REQUEST;
                case FINGERPRINT_MISMATCH -> RunnerReasonCode.RUNNER_REQUEST_FINGERPRINT_MISMATCH;
                case INCOMPLETE_PRIOR_CLAIM -> RunnerReasonCode.RUNNER_REQUEST_INCOMPLETE;
                // AMBIGUOUS: the claim statement reached the database but this caller could not
                // observe whether it committed - never treated as claimed, never retried here. A
                // fresh resubmission of the same runnerRequestId is what safely resolves it (see
                // RunnerClaimOutcome#AMBIGUOUS).
                case AMBIGUOUS -> RunnerReasonCode.RUNNER_LEDGER_CLAIM_AMBIGUOUS;
                case CLAIMED -> throw new IllegalStateException("unreachable");
            };
            return evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED,
                    List.of(reason), null, null, null, null, null);
        }
        // state: REQUEST_CLAIMED

        PipelineOutcome outcome = runClaimedPipeline(request, startedAt);

        try {
            ledger.recordTerminalEvidence(outcome.evidence());
        } catch (RunnerLedgerPersistenceException e) {
            cleanupQuietly(outcome.workspace());
            // The pipeline may have computed READY_FOR_FUTURE_EXECUTION, but if that outcome
            // cannot be durably recorded, it must never be handed to the caller as authoritative -
            // a restart right now would lose all memory of this decision, and a resubmission would
            // be re-validated from scratch against possibly-different approval state, which is
            // exactly the kind of inconsistency durable replay protection exists to prevent.
            return evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED,
                    List.of(RunnerReasonCode.RUNNER_LEDGER_UNAVAILABLE), null, null, null, null, null);
        }
        cleanupQuietly(outcome.workspace());
        return outcome.evidence();
    }

    /**
     * The original, immutable evidence for a {@code runnerRequestId}, kept for audit purposes.
     * Backed by the durable ledger - deliberately a separate accessor from {@link #execute}: a
     * caller must not be able to confuse "here is what happened historically" with "this request
     * is currently authorized" - only the return value of a request's own first successful claim
     * is ever the latter.
     */
    public Optional<RunnerEvidence> historicalEvidence(String runnerRequestId) {
        return ledger.findHistoricalEvidence(runnerRequestId);
    }

    private void cleanupQuietly(Path workspace) {
        if (workspace != null) {
            workspaceManager.cleanup(workspace);
        }
    }

    /** Carries the terminal evidence alongside the workspace (if any) that should be cleaned up
     * once that evidence has been durably recorded - never before. */
    private record PipelineOutcome(RunnerEvidence evidence, Path workspace) {
    }

    private PipelineOutcome runClaimedPipeline(RunnerRequest request, Instant startedAt) {
        // --- Identity: host-derived, never request-derived ---
        Optional<RunnerIdentity> maybeIdentity;
        try {
            maybeIdentity = identityProvider.currentIdentity();
        } catch (RuntimeException e) {
            return blocked(request, startedAt, RunnerReasonCode.RUNNER_IDENTITY_UNAVAILABLE, null, null, null, null, null);
        }
        if (maybeIdentity.isEmpty()) {
            return blocked(request, startedAt, RunnerReasonCode.RUNNER_IDENTITY_UNAVAILABLE, null, null, null, null, null);
        }
        RunnerIdentity identity = maybeIdentity.get();
        if (!identity.trusted()) {
            return blocked(request, startedAt, RunnerReasonCode.RUNNER_IDENTITY_UNTRUSTED, identity, null, null, null, null);
        }
        if (!identity.environmentScope().contains(request.environment())) {
            return blocked(request, startedAt, RunnerReasonCode.RUNNER_ENVIRONMENT_NOT_ALLOWED, identity, null, null, null, null);
        }
        if (!allowedRunnerClasses.contains(identity.runnerClass())) {
            return blocked(request, startedAt, RunnerReasonCode.RUNNER_CLASS_NOT_ALLOWED, identity, null, null, null, null);
        }
        // state: IDENTITY_RESOLVED

        // --- Approval: read-only ApprovalProvider, reusing the shared ApprovalValidator rather
        // than reimplementing identity/expiry/revocation/supersession comparison logic. ---
        ApprovalValidationResult approvalResult;
        try {
            ExecutionIdentity executionIdentity = new ExecutionIdentity(request.repository(), request.commitSha(), request.environment(), request.planSha256());
            approvalResult = ApprovalValidator.validate(approvalProvider, request.approvalId(), executionIdentity, clock.instant());
        } catch (ApprovalPersistenceException e) {
            return blocked(request, startedAt, RunnerReasonCode.DURABLE_APPROVAL_STORE_UNAVAILABLE, identity, null, null, null, null);
        }
        if (!approvalResult.isValid()) {
            RunnerReasonCode reason = mapApprovalReason(approvalResult.reasonCode());
            return blocked(request, startedAt, reason, identity, null, approvalResult.reasonCode(), null, null);
        }
        // state: APPROVAL_RESOLVED

        if (request.requestedOperation() == RunnerOperation.VERIFY_CONTEXT) {
            return verifyContext(request, startedAt, identity, approvalResult.reasonCode());
        }

        // --- Phase 2B-3: TERRAFORM_VERSION needs no artifact at all - it only asks whether the
        // trusted binary is the version we expect. ---
        if (request.requestedOperation() == RunnerOperation.TERRAFORM_VERSION) {
            return runTerraformVersion(request, startedAt, identity, approvalResult.reasonCode());
        }

        // --- Artifact: independently resolved and re-hashed, never trusted from the request or
        // from the store's own recorded hash alone. Shared by VERIFY_ARTIFACT, PREPARE_EXECUTION,
        // and the two remaining Phase 2B-3 operations - only the staging call differs. ---
        Optional<StoredArtifact> stored = artifactStore.resolve(request.planArtifactId());
        if (stored.isEmpty()) {
            return blocked(request, startedAt, RunnerReasonCode.ARTIFACT_NOT_FOUND, identity, null, approvalResult.reasonCode(), null, null);
        }
        // state: ARTIFACT_RESOLVED
        String observedSha256 = sha256Hex(stored.get().content());
        if (!observedSha256.equals(stored.get().recordedSha256()) || !observedSha256.equals(request.planSha256())) {
            return blockedWithObservedHash(request, startedAt, RunnerReasonCode.ARTIFACT_HASH_MISMATCH,
                    identity, observedSha256, approvalResult.reasonCode());
        }

        Path workspace;
        Path stagedPath;
        try {
            workspace = workspaceManager.createWorkspace(request.runnerRequestId());
            stagedPath = isTerraformConfigOperation(request.requestedOperation())
                    ? workspaceManager.stageTerraformConfigFile(workspace, observedSha256, stored.get().content())
                    : workspaceManager.stageArtifact(workspace, observedSha256, stored.get().content());
        } catch (RuntimeException e) {
            return blockedWithObservedHash(request, startedAt, RunnerReasonCode.ARTIFACT_STAGING_FAILURE,
                    identity, observedSha256, approvalResult.reasonCode());
        }
        // state: ARTIFACT_VERIFIED

        if (request.requestedOperation() == RunnerOperation.VERIFY_ARTIFACT) {
            RunnerEvidence evidence = evidenceOf(request, startedAt, clock.instant(), RunnerState.ARTIFACT_VERIFIED, List.of(),
                    identity, observedSha256, approvalResult.reasonCode(), null, null);
            return new PipelineOutcome(evidence, workspace);
        }

        if (request.requestedOperation() == RunnerOperation.TERRAFORM_FMT_CHECK) {
            return runTerraformFmtCheck(request, startedAt, identity, observedSha256, approvalResult.reasonCode(), workspace);
        }

        if (request.requestedOperation() == RunnerOperation.TERRAFORM_SHOW_PLAN_JSON) {
            return runTerraformShowPlanJson(request, startedAt, identity, observedSha256, approvalResult.reasonCode(), workspace, stagedPath);
        }

        if (request.requestedOperation() == RunnerOperation.TERRAFORM_INIT) {
            return runTerraformInit(request, startedAt, identity, observedSha256, approvalResult.reasonCode(), workspace, stored.get().content());
        }

        if (request.requestedOperation() == RunnerOperation.TERRAFORM_VALIDATE) {
            return runTerraformValidate(request, startedAt, identity, observedSha256, approvalResult.reasonCode(), workspace, stored.get().content());
        }

        if (request.requestedOperation() == RunnerOperation.TERRAFORM_PROVIDERS_SCHEMA) {
            return runTerraformProvidersSchema(request, startedAt, identity, observedSha256, approvalResult.reasonCode(), workspace, stored.get().content());
        }

        if (request.requestedOperation() == RunnerOperation.TERRAFORM_PLAN) {
            return runTerraformPlan(request, startedAt, identity, observedSha256, approvalResult.reasonCode(), workspace, stored.get().content());
        }

        // --- Context: runner-observed Terraform version / provider-lock hash, never the
        // request's own claim alone. PREPARE_EXECUTION only. ---
        String observedTerraformVersion = toolchainContext.observedTerraformVersion();
        if (!observedTerraformVersion.equals(request.terraformVersion())) {
            RunnerEvidence evidence = evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED, List.of(RunnerReasonCode.TERRAFORM_VERSION_MISMATCH),
                    identity, observedSha256, approvalResult.reasonCode(), observedTerraformVersion, null);
            return new PipelineOutcome(evidence, workspace);
        }
        String observedProviderLockHash = toolchainContext.observedProviderLockHash();
        if (!observedProviderLockHash.equals(request.providerLockHash())) {
            RunnerEvidence evidence = evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED, List.of(RunnerReasonCode.PROVIDER_LOCK_HASH_MISMATCH),
                    identity, observedSha256, approvalResult.reasonCode(), observedTerraformVersion, observedProviderLockHash);
            return new PipelineOutcome(evidence, workspace);
        }
        // state: CONTEXT_VERIFIED -> READY_FOR_FUTURE_EXECUTION

        RunnerEvidence evidence = evidenceOf(request, startedAt, clock.instant(), RunnerState.READY_FOR_FUTURE_EXECUTION, List.of(),
                identity, observedSha256, approvalResult.reasonCode(), observedTerraformVersion, observedProviderLockHash);
        return new PipelineOutcome(evidence, workspace);
    }

    private PipelineOutcome verifyContext(RunnerRequest request, Instant startedAt, RunnerIdentity identity, ApprovalValidationReasonCode approvalReason) {
        String observedTerraformVersion = toolchainContext.observedTerraformVersion();
        if (!observedTerraformVersion.equals(request.terraformVersion())) {
            return blockedWithContext(request, startedAt, RunnerReasonCode.TERRAFORM_VERSION_MISMATCH, identity, approvalReason, observedTerraformVersion, null);
        }
        String observedProviderLockHash = toolchainContext.observedProviderLockHash();
        if (!observedProviderLockHash.equals(request.providerLockHash())) {
            return blockedWithContext(request, startedAt, RunnerReasonCode.PROVIDER_LOCK_HASH_MISMATCH, identity, approvalReason, observedTerraformVersion, observedProviderLockHash);
        }
        RunnerEvidence evidence = evidenceOf(request, startedAt, clock.instant(), RunnerState.CONTEXT_VERIFIED, List.of(),
                identity, null, approvalReason, observedTerraformVersion, observedProviderLockHash);
        return new PipelineOutcome(evidence, null);
    }

    /**
     * Phase 2B-3: {@code TERRAFORM_VERSION} needs a fresh workspace (as a Terraform working
     * directory) but no plan/config artifact - the request is still scoped to a specific
     * approval/plan context, but this operation itself never touches that plan's content.
     */
    private PipelineOutcome runTerraformVersion(RunnerRequest request, Instant startedAt, RunnerIdentity identity, ApprovalValidationReasonCode approvalReason) {
        if (terraformCoordinator == null) {
            return blocked(request, startedAt, RunnerReasonCode.TERRAFORM_OPERATION_NOT_ALLOWED, identity, null, approvalReason, null, null);
        }
        Path workspace;
        try {
            workspace = workspaceManager.createWorkspace(request.runnerRequestId());
        } catch (RuntimeException e) {
            return blocked(request, startedAt, RunnerReasonCode.WORKSPACE_ISOLATION_FAILURE, identity, null, approvalReason, null, null);
        }
        TerraformProcessEvidence tfEvidence = terraformCoordinator.executeVersion(request, identity, workspace);
        return fromTerraformEvidence(request, startedAt, identity, null, approvalReason, tfEvidence, workspace);
    }

    /** Phase 2B-3: {@code TERRAFORM_FMT_CHECK} - the artifact/workspace staging already happened
     * in {@link #runClaimedPipeline} (staged as a {@code .tf} file, not {@code .tfplan}) before
     * this is called. */
    private PipelineOutcome runTerraformFmtCheck(
            RunnerRequest request, Instant startedAt, RunnerIdentity identity, String observedSha256, ApprovalValidationReasonCode approvalReason, Path workspace) {
        if (terraformCoordinator == null) {
            RunnerEvidence evidence = evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED,
                    List.of(RunnerReasonCode.TERRAFORM_OPERATION_NOT_ALLOWED), identity, observedSha256, approvalReason, null, null);
            return new PipelineOutcome(evidence, workspace);
        }
        TerraformProcessEvidence tfEvidence = terraformCoordinator.executeFmtCheck(request, identity, workspace);
        return fromTerraformEvidence(request, startedAt, identity, observedSha256, approvalReason, tfEvidence, workspace);
    }

    /** Phase 2B-3: {@code TERRAFORM_SHOW_PLAN_JSON} - {@code stagedPlanPath} is always the
     * already-hash-verified, runner-staged plan from {@link #runClaimedPipeline}; the coordinator
     * still re-verifies its hash immediately before launching {@code terraform show} (the final
     * TOCTOU check), never trusting this earlier verification alone. */
    private PipelineOutcome runTerraformShowPlanJson(RunnerRequest request, Instant startedAt, RunnerIdentity identity, String observedSha256,
                                                      ApprovalValidationReasonCode approvalReason, Path workspace, Path stagedPlanPath) {
        if (terraformCoordinator == null) {
            RunnerEvidence evidence = evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED,
                    List.of(RunnerReasonCode.TERRAFORM_OPERATION_NOT_ALLOWED), identity, observedSha256, approvalReason, null, null);
            return new PipelineOutcome(evidence, workspace);
        }
        TerraformProcessEvidence tfEvidence = terraformCoordinator.executeShowPlanJson(request, identity, workspace, stagedPlanPath, observedSha256);
        return fromTerraformEvidence(request, startedAt, identity, observedSha256, approvalReason, tfEvidence, workspace);
    }

    /** Phase 2B-4: {@code TERRAFORM_INIT} - the config artifact is staged as a {@code .tf} file
     * exactly like {@code TERRAFORM_FMT_CHECK} before this is called; {@code configContent} is
     * passed through so the coordinator can compute a configuration identity and run its pre-init
     * source-policy scan without re-reading the staged file from disk. */
    private PipelineOutcome runTerraformInit(RunnerRequest request, Instant startedAt, RunnerIdentity identity, String observedSha256,
                                              ApprovalValidationReasonCode approvalReason, Path workspace, byte[] configContent) {
        if (terraformCoordinator == null) {
            RunnerEvidence evidence = evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED,
                    List.of(RunnerReasonCode.TERRAFORM_OPERATION_NOT_ALLOWED), identity, observedSha256, approvalReason, null, null);
            return new PipelineOutcome(evidence, workspace);
        }
        TerraformInitEvidence initEvidence = terraformCoordinator.executeInit(request, identity, workspace, configFilesFor(configContent));
        return fromTerraformInitEvidence(request, startedAt, identity, observedSha256, approvalReason, initEvidence, workspace);
    }

    /** Phase 2B-4: {@code TERRAFORM_VALIDATE} - the coordinator internally runs the same controlled
     * init sequence {@link #runTerraformInit} uses before validate itself is ever launched. */
    private PipelineOutcome runTerraformValidate(RunnerRequest request, Instant startedAt, RunnerIdentity identity, String observedSha256,
                                                  ApprovalValidationReasonCode approvalReason, Path workspace, byte[] configContent) {
        if (terraformCoordinator == null) {
            RunnerEvidence evidence = evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED,
                    List.of(RunnerReasonCode.TERRAFORM_OPERATION_NOT_ALLOWED), identity, observedSha256, approvalReason, null, null);
            return new PipelineOutcome(evidence, workspace);
        }
        TerraformValidateEvidence validateEvidence = terraformCoordinator.executeValidate(request, identity, workspace, configFilesFor(configContent));
        return fromTerraformValidateEvidence(request, startedAt, identity, observedSha256, approvalReason, validateEvidence, workspace);
    }

    /** Phase 2B-4: {@code TERRAFORM_PROVIDERS_SCHEMA} - the coordinator internally runs the same
     * controlled init sequence {@link #runTerraformInit} uses before providers-schema is launched. */
    private PipelineOutcome runTerraformProvidersSchema(RunnerRequest request, Instant startedAt, RunnerIdentity identity, String observedSha256,
                                                         ApprovalValidationReasonCode approvalReason, Path workspace, byte[] configContent) {
        if (terraformCoordinator == null) {
            RunnerEvidence evidence = evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED,
                    List.of(RunnerReasonCode.TERRAFORM_OPERATION_NOT_ALLOWED), identity, observedSha256, approvalReason, null, null);
            return new PipelineOutcome(evidence, workspace);
        }
        TerraformProviderSchemaEvidence schemaEvidence = terraformCoordinator.executeProvidersSchema(request, identity, workspace, configFilesFor(configContent));
        return fromTerraformProviderSchemaEvidence(request, startedAt, identity, observedSha256, approvalReason, schemaEvidence, workspace);
    }

    /** Phase 2B-5: {@code TERRAFORM_PLAN} - produces a real, saved plan artifact against a trusted,
     * control-plane-resolved backend/state target. Still no infrastructure/state mutation: a plan
     * reads state and may read provider APIs, but never writes state or applies anything. */
    private PipelineOutcome runTerraformPlan(RunnerRequest request, Instant startedAt, RunnerIdentity identity, String observedSha256,
                                              ApprovalValidationReasonCode approvalReason, Path workspace, byte[] configContent) {
        if (terraformCoordinator == null) {
            RunnerEvidence evidence = evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED,
                    List.of(RunnerReasonCode.TERRAFORM_OPERATION_NOT_ALLOWED), identity, observedSha256, approvalReason, null, null);
            return new PipelineOutcome(evidence, workspace);
        }
        TerraformPlanEvidence planEvidence = terraformCoordinator.executePlan(request, identity, workspace, configFilesFor(configContent));
        return fromTerraformPlanEvidence(request, startedAt, identity, observedSha256, approvalReason, planEvidence, workspace);
    }

    /** Wraps the request's single resolved config-artifact blob into the
     * {@link TerraformConfigIdentity.NamedConfigFile} shape the coordinator's Phase 2B-4 methods
     * require. {@code SINGLE_ARTIFACT_CONFIG_FILE_NAME} is a fixed constant, never a caller/
     * repository-supplied name - this runner's current request contract resolves exactly one
     * pre-hashed artifact per request (the same single-artifact model {@code TERRAFORM_FMT_CHECK}
     * already uses), so there is no real "original filename" to preserve yet. A future phase that
     * wires {@link RunnerWorkspaceManager#stageTerraformConfigDirectory} in would supply the
     * genuine repository-relative filenames instead - see {@code docs/phase-2b4-controlled-init-validation.md}
     * §10. */
    private static final String SINGLE_ARTIFACT_CONFIG_FILE_NAME = "config.tf";

    private static List<TerraformConfigIdentity.NamedConfigFile> configFilesFor(byte[] content) {
        return List.of(new TerraformConfigIdentity.NamedConfigFile(SINGLE_ARTIFACT_CONFIG_FILE_NAME, content));
    }

    private PipelineOutcome fromTerraformInitEvidence(RunnerRequest request, Instant startedAt, RunnerIdentity identity, String observedPlanSha256,
                                                       ApprovalValidationReasonCode approvalReason, TerraformInitEvidence initEvidence, Path workspace) {
        RunnerState finalState = initEvidence.succeeded() ? RunnerState.TERRAFORM_PROCESS_COMPLETED : RunnerState.BLOCKED;
        RunnerEvidence evidence = new RunnerEvidence(
                request.runnerRequestId(), identity == null ? null : identity.runnerId(), identity == null ? null : identity.runnerClass(),
                identity == null ? Set.of() : identity.environmentScope(), request.requestedOperation(), request.repository(), request.commitSha(),
                request.environment(), request.planArtifactId(), request.planSha256(), observedPlanSha256, request.terraformVersion(),
                initEvidence.terraformVersionObserved(), request.providerLockHash(), null, request.approvalId(), approvalReason, finalState,
                initEvidence.reasonCodes(), startedAt, initEvidence.completedAt(), null, initEvidence, null, null);
        return new PipelineOutcome(evidence, workspace);
    }

    private PipelineOutcome fromTerraformValidateEvidence(RunnerRequest request, Instant startedAt, RunnerIdentity identity, String observedPlanSha256,
                                                           ApprovalValidationReasonCode approvalReason, TerraformValidateEvidence validateEvidence, Path workspace) {
        boolean succeeded = validateEvidence.processState() == TerraformProcessState.SUCCEEDED
                || validateEvidence.processState() == TerraformProcessState.COMMAND_REPORTED_DIFFERENCE;
        RunnerState finalState = succeeded ? RunnerState.TERRAFORM_PROCESS_COMPLETED : RunnerState.BLOCKED;
        RunnerEvidence evidence = new RunnerEvidence(
                request.runnerRequestId(), identity == null ? null : identity.runnerId(), identity == null ? null : identity.runnerClass(),
                identity == null ? Set.of() : identity.environmentScope(), request.requestedOperation(), request.repository(), request.commitSha(),
                request.environment(), request.planArtifactId(), request.planSha256(), observedPlanSha256, request.terraformVersion(),
                validateEvidence.initEvidence().terraformVersionObserved(), request.providerLockHash(), null, request.approvalId(), approvalReason,
                finalState, validateEvidence.reasonCodes(), startedAt, validateEvidence.completedAt(), null, null, validateEvidence, null);
        return new PipelineOutcome(evidence, workspace);
    }

    private PipelineOutcome fromTerraformProviderSchemaEvidence(RunnerRequest request, Instant startedAt, RunnerIdentity identity, String observedPlanSha256,
                                                                 ApprovalValidationReasonCode approvalReason, TerraformProviderSchemaEvidence schemaEvidence, Path workspace) {
        RunnerState finalState = schemaEvidence.processState() == TerraformProcessState.SUCCEEDED ? RunnerState.TERRAFORM_PROCESS_COMPLETED : RunnerState.BLOCKED;
        RunnerEvidence evidence = new RunnerEvidence(
                request.runnerRequestId(), identity == null ? null : identity.runnerId(), identity == null ? null : identity.runnerClass(),
                identity == null ? Set.of() : identity.environmentScope(), request.requestedOperation(), request.repository(), request.commitSha(),
                request.environment(), request.planArtifactId(), request.planSha256(), observedPlanSha256, request.terraformVersion(),
                schemaEvidence.terraformVersionObserved(), request.providerLockHash(), null, request.approvalId(), approvalReason,
                finalState, schemaEvidence.reasonCodes(), startedAt, schemaEvidence.completedAt(), null, null, null, schemaEvidence);
        return new PipelineOutcome(evidence, workspace);
    }

    private PipelineOutcome fromTerraformPlanEvidence(RunnerRequest request, Instant startedAt, RunnerIdentity identity, String observedPlanSha256,
                                                       ApprovalValidationReasonCode approvalReason, TerraformPlanEvidence planEvidence, Path workspace) {
        RunnerState finalState = planEvidence.succeeded() ? RunnerState.TERRAFORM_PROCESS_COMPLETED : RunnerState.BLOCKED;
        RunnerEvidence evidence = new RunnerEvidence(
                request.runnerRequestId(), identity == null ? null : identity.runnerId(), identity == null ? null : identity.runnerClass(),
                identity == null ? Set.of() : identity.environmentScope(), request.requestedOperation(), request.repository(), request.commitSha(),
                request.environment(), request.planArtifactId(), request.planSha256(), observedPlanSha256, request.terraformVersion(),
                planEvidence.terraformVersionObserved(), request.providerLockHash(), null, request.approvalId(), approvalReason,
                finalState, planEvidence.reasonCodes(), startedAt, planEvidence.completedAt(), null, null, null, null, planEvidence);
        return new PipelineOutcome(evidence, workspace);
    }

    /** Maps a {@link TerraformProcessEvidence} into the enclosing {@link RunnerEvidence}/
     * {@link RunnerState}: {@code SUCCEEDED} and {@code COMMAND_REPORTED_DIFFERENCE} (fmt-check
     * found differences - a legitimate, deterministic outcome, never a failure) both become
     * {@link RunnerState#TERRAFORM_PROCESS_COMPLETED}; every other {@link TerraformProcessState}
     * becomes {@link RunnerState#BLOCKED}, carrying whatever reason codes the coordinator already
     * attached. */
    private PipelineOutcome fromTerraformEvidence(RunnerRequest request, Instant startedAt, RunnerIdentity identity, String observedPlanSha256,
                                                   ApprovalValidationReasonCode approvalReason, TerraformProcessEvidence tfEvidence, Path workspace) {
        boolean succeeded = tfEvidence.processState() == TerraformProcessState.SUCCEEDED
                || tfEvidence.processState() == TerraformProcessState.COMMAND_REPORTED_DIFFERENCE;
        RunnerState finalState = succeeded ? RunnerState.TERRAFORM_PROCESS_COMPLETED : RunnerState.BLOCKED;
        RunnerEvidence evidence = evidenceOf(request, startedAt, tfEvidence.completedAt(), finalState, tfEvidence.reasonCodes(),
                identity, observedPlanSha256, approvalReason, tfEvidence.terraformVersionObserved(), null, tfEvidence);
        return new PipelineOutcome(evidence, workspace);
    }

    private PipelineOutcome blockedWithContext(RunnerRequest request, Instant startedAt, RunnerReasonCode reason, RunnerIdentity identity,
                                                ApprovalValidationReasonCode approvalReason, String tfObserved, String lockObserved) {
        RunnerEvidence evidence = evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED, List.of(reason),
                identity, null, approvalReason, tfObserved, lockObserved);
        return new PipelineOutcome(evidence, null);
    }

    private PipelineOutcome blocked(RunnerRequest request, Instant startedAt, RunnerReasonCode reason, RunnerIdentity identity,
                                     String observedPlanSha256, ApprovalValidationReasonCode approvalReason,
                                     String tfObserved, String lockObserved) {
        RunnerEvidence evidence = evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED, List.of(reason),
                identity, observedPlanSha256, approvalReason, tfObserved, lockObserved);
        return new PipelineOutcome(evidence, null);
    }

    private PipelineOutcome blockedWithObservedHash(RunnerRequest request, Instant startedAt, RunnerReasonCode reason,
                                                     RunnerIdentity identity, String observedPlanSha256, ApprovalValidationReasonCode approvalReason) {
        return blocked(request, startedAt, reason, identity, observedPlanSha256, approvalReason, null, null);
    }

    private static RunnerReasonCode mapApprovalReason(ApprovalValidationReasonCode reason) {
        return switch (reason) {
            case APPROVAL_NOT_FOUND -> RunnerReasonCode.APPROVAL_NOT_FOUND;
            case REPOSITORY_MISMATCH -> RunnerReasonCode.REPOSITORY_MISMATCH;
            case COMMIT_SHA_MISMATCH -> RunnerReasonCode.COMMIT_SHA_MISMATCH;
            case ENVIRONMENT_MISMATCH -> RunnerReasonCode.ENVIRONMENT_MISMATCH;
            case PLAN_HASH_MISMATCH -> RunnerReasonCode.PLAN_HASH_MISMATCH;
            case APPROVAL_EXPIRED -> RunnerReasonCode.APPROVAL_EXPIRED;
            case APPROVAL_REVOKED -> RunnerReasonCode.APPROVAL_REVOKED;
            case APPROVAL_SUPERSEDED -> RunnerReasonCode.APPROVAL_SUPERSEDED;
            case VALID -> throw new IllegalStateException("mapApprovalReason must not be called for a VALID result");
        };
    }

    private RunnerEvidence evidenceOf(
            RunnerRequest request, Instant startedAt, Instant completedAt, RunnerState finalState, List<RunnerReasonCode> reasonCodes,
            RunnerIdentity identity, String observedPlanSha256, ApprovalValidationReasonCode approvalReason,
            String terraformVersionObserved, String providerLockHashObserved
    ) {
        return evidenceOf(request, startedAt, completedAt, finalState, reasonCodes, identity, observedPlanSha256, approvalReason,
                terraformVersionObserved, providerLockHashObserved, null);
    }

    private RunnerEvidence evidenceOf(
            RunnerRequest request, Instant startedAt, Instant completedAt, RunnerState finalState, List<RunnerReasonCode> reasonCodes,
            RunnerIdentity identity, String observedPlanSha256, ApprovalValidationReasonCode approvalReason,
            String terraformVersionObserved, String providerLockHashObserved, TerraformProcessEvidence terraformProcessEvidence
    ) {
        return new RunnerEvidence(
                request.runnerRequestId(),
                identity == null ? null : identity.runnerId(),
                identity == null ? null : identity.runnerClass(),
                identity == null ? Set.of() : identity.environmentScope(),
                request.requestedOperation(),
                request.repository(),
                request.commitSha(),
                request.environment(),
                request.planArtifactId(),
                request.planSha256(),
                observedPlanSha256,
                request.terraformVersion(),
                terraformVersionObserved,
                request.providerLockHash(),
                providerLockHashObserved,
                request.approvalId(),
                approvalReason,
                finalState,
                reasonCodes,
                startedAt,
                completedAt,
                terraformProcessEvidence
        );
    }

    private static String sha256Hex(byte[] content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(content));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available on any supported JVM", e);
        }
    }
}
