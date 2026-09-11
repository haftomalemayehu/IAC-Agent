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
        this.identityProvider = require(identityProvider, "identityProvider");
        this.allowedRunnerClasses = allowedRunnerClasses == null ? Set.of() : Set.copyOf(allowedRunnerClasses);
        this.approvalProvider = require(approvalProvider, "approvalProvider");
        this.artifactStore = require(artifactStore, "artifactStore");
        this.toolchainContext = require(toolchainContext, "toolchainContext");
        this.workspaceManager = require(workspaceManager, "workspaceManager");
        this.ledger = require(ledger, "ledger");
        this.clock = require(clock, "clock");
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

        // --- Artifact: independently resolved and re-hashed, never trusted from the request or
        // from the store's own recorded hash alone. ---
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
        try {
            workspace = workspaceManager.createWorkspace(request.runnerRequestId());
            workspaceManager.stageArtifact(workspace, observedSha256, stored.get().content());
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
                completedAt
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
