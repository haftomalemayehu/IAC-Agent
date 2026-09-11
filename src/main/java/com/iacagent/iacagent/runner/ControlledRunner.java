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
import java.util.concurrent.ConcurrentHashMap;

/**
 * Phase 2B-1's controlled runner boundary. Exposes exactly one entry point,
 * {@link #execute(RunnerRequest)}, taking a fully typed {@link RunnerRequest} with a closed
 * {@link RunnerOperation}. There is no {@code execute(String command)}, no shell/process
 * invocation, and no operation value that represents infrastructure mutation anywhere in this
 * class or this package - no type in this package spawns an external process at all, and that is
 * a design property to preserve (see {@code Phase2b1Tests#runnerPackageContainsNoProcessInvocation}),
 * not an incidental fact about this commit.
 *
 * <p>Consumes {@link ApprovalProvider} - read-only - never {@code ApprovalAuthority}. This class
 * has no way to issue, revoke, or supersede an approval; it can only ask whether one is valid for
 * a given identity, exactly like the future Phase 2A executor will.
 *
 * <p>Identity is resolved exclusively via the injected {@link RunnerIdentityProvider}, never from
 * {@code request} - {@link RunnerRequest} has no identity-shaped field to read one from even if a
 * caller wanted to supply one.
 */
public final class ControlledRunner {

    private final RunnerIdentityProvider identityProvider;
    private final ApprovalProvider approvalProvider;
    private final RunnerArtifactStore artifactStore;
    private final RunnerToolchainContext toolchainContext;
    private final RunnerWorkspaceManager workspaceManager;
    private final Clock clock;

    private final ConcurrentHashMap<String, Object> perRequestLocks = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, RunnerRequest> requestFingerprints = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, RunnerEvidence> evidenceLedger = new ConcurrentHashMap<>();

    public ControlledRunner(
            RunnerIdentityProvider identityProvider,
            ApprovalProvider approvalProvider,
            RunnerArtifactStore artifactStore,
            RunnerToolchainContext toolchainContext,
            RunnerWorkspaceManager workspaceManager,
            Clock clock
    ) {
        this.identityProvider = require(identityProvider, "identityProvider");
        this.approvalProvider = require(approvalProvider, "approvalProvider");
        this.artifactStore = require(artifactStore, "artifactStore");
        this.toolchainContext = require(toolchainContext, "toolchainContext");
        this.workspaceManager = require(workspaceManager, "workspaceManager");
        this.clock = require(clock, "clock");
    }

    private static <T> T require(T value, String name) {
        if (value == null) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }

    /**
     * Idempotency policy: cached replay. A resubmission of the same {@code runnerRequestId} with
     * byte-for-byte identical request content returns the original, immutable evidence rather than
     * re-executing it and, critically, WITHOUT ever returning the original evidence as if it were
     * a fresh authorization decision. A prior {@link RunnerEvidence} - even one that reached
     * {@link RunnerState#READY_FOR_FUTURE_EXECUTION} - is historical evidence, not a current
     * authorization: approval validity is time-varying and externally revocable (see
     * {@code ApprovalRecordProducer#revoke}/{@code #issueSuperseding}), so an approval that was
     * ACTIVE at the time of the original submission may be REVOKED, SUPERSEDED, or simply expired
     * by the time of a later resubmission under the same id. Returning the cached
     * READY_FOR_FUTURE_EXECUTION result for that resubmission would let a historical readiness
     * result silently outlive the approval it was originally validated against - exactly the kind
     * of stale-authorization bug this package exists to prevent elsewhere (see the Phase 2A
     * execution contract's own plan-hash lineage invariant). So:
     *
     * <pre>
     * first submission of a runnerRequestId          -&gt; processed normally
     * same id, byte-for-byte identical request again -&gt; BLOCKED / DUPLICATE_RUNNER_REQUEST
     * same id, DIFFERENT request content              -&gt; BLOCKED / RUNNER_REQUEST_FINGERPRINT_MISMATCH
     * </pre>
     *
     * Neither duplicate case re-executes the pipeline or reads current approval/artifact state.
     * The original evidence remains available for audit via {@link #historicalEvidence(String)},
     * clearly separated from "the result of this call."
     *
     * <p>Concurrency: each {@code runnerRequestId} gets its own monitor (via
     * {@code perRequestLocks}), so two different ids proceed fully concurrently - only two
     * callers racing on the SAME id serialize against each other.
     */
    public RunnerEvidence execute(RunnerRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request is required");
        }
        Object requestLock = perRequestLocks.computeIfAbsent(request.runnerRequestId(), id -> new Object());
        synchronized (requestLock) {
            RunnerRequest priorFingerprint = requestFingerprints.get(request.runnerRequestId());
            if (priorFingerprint != null) {
                Instant now = clock.instant();
                RunnerReasonCode reason = request.equals(priorFingerprint)
                        ? RunnerReasonCode.DUPLICATE_RUNNER_REQUEST
                        : RunnerReasonCode.RUNNER_REQUEST_FINGERPRINT_MISMATCH;
                return evidenceOf(request, now, now, RunnerState.BLOCKED, List.of(reason), null, null, null, null, null);
            }
            requestFingerprints.put(request.runnerRequestId(), request);
            RunnerEvidence result = runPipeline(request);
            evidenceLedger.put(request.runnerRequestId(), result);
            return result;
        }
    }

    /**
     * The original, immutable evidence for a {@code runnerRequestId}, kept for audit purposes.
     * This is deliberately a separate accessor from {@link #execute}: a caller must not be able to
     * confuse "here is what happened historically" with "this request is currently authorized" -
     * only the return value of a request's own first {@link #execute} call is ever the latter.
     */
    public Optional<RunnerEvidence> historicalEvidence(String runnerRequestId) {
        return Optional.ofNullable(evidenceLedger.get(runnerRequestId));
    }

    private RunnerEvidence runPipeline(RunnerRequest request) {
        Instant startedAt = clock.instant();

        // --- Identity: host-derived, never request-derived ---
        RunnerIdentity identity = identityProvider.currentIdentity();
        if (!identity.trusted()) {
            return evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED, List.of(RunnerReasonCode.RUNNER_IDENTITY_UNTRUSTED),
                    identity.runnerId(), null, null, null, null);
        }
        if (!identity.environmentScope().contains(request.environment())) {
            return evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED, List.of(RunnerReasonCode.RUNNER_ENVIRONMENT_NOT_ALLOWED),
                    identity.runnerId(), null, null, null, null);
        }
        // state: IDENTITY_RESOLVED

        // --- Approval: read-only ApprovalProvider, reusing the shared ApprovalValidator rather
        // than reimplementing identity/expiry/revocation/supersession comparison logic. ---
        ApprovalValidationResult approvalResult;
        try {
            ExecutionIdentity executionIdentity = new ExecutionIdentity(request.repository(), request.commitSha(), request.environment(), request.planSha256());
            approvalResult = ApprovalValidator.validate(approvalProvider, request.approvalId(), executionIdentity, clock.instant());
        } catch (ApprovalPersistenceException e) {
            return evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED, List.of(RunnerReasonCode.DURABLE_APPROVAL_STORE_UNAVAILABLE),
                    identity.runnerId(), null, null, null, null);
        }
        if (!approvalResult.isValid()) {
            RunnerReasonCode reason = mapApprovalReason(approvalResult.reasonCode());
            return evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED, List.of(reason),
                    identity.runnerId(), null, approvalResult.reasonCode(), null, null);
        }
        // state: APPROVAL_RESOLVED

        if (request.requestedOperation() == RunnerOperation.VERIFY_CONTEXT) {
            return verifyContext(request, startedAt, identity.runnerId(), approvalResult.reasonCode());
        }

        // --- Artifact: independently resolved and re-hashed, never trusted from the request or
        // from the store's own recorded hash alone. ---
        Optional<StoredArtifact> stored = artifactStore.resolve(request.planArtifactId());
        if (stored.isEmpty()) {
            return evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED, List.of(RunnerReasonCode.ARTIFACT_NOT_FOUND),
                    identity.runnerId(), null, approvalResult.reasonCode(), null, null);
        }
        // state: ARTIFACT_RESOLVED
        String observedSha256 = sha256Hex(stored.get().content());
        if (!observedSha256.equals(stored.get().recordedSha256()) || !observedSha256.equals(request.planSha256())) {
            return evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED, List.of(RunnerReasonCode.ARTIFACT_HASH_MISMATCH),
                    identity.runnerId(), observedSha256, approvalResult.reasonCode(), null, null);
        }
        Path workspace = workspaceManager.createWorkspace(request.runnerRequestId());
        workspaceManager.stageArtifact(workspace, observedSha256, stored.get().content());
        // state: ARTIFACT_VERIFIED

        if (request.requestedOperation() == RunnerOperation.VERIFY_ARTIFACT) {
            return evidenceOf(request, startedAt, clock.instant(), RunnerState.ARTIFACT_VERIFIED, List.of(),
                    identity.runnerId(), observedSha256, approvalResult.reasonCode(), null, null);
        }

        // --- Context: runner-observed Terraform version / provider-lock hash, never the
        // request's own claim alone. PREPARE_EXECUTION only. ---
        String observedTerraformVersion = toolchainContext.observedTerraformVersion();
        if (!observedTerraformVersion.equals(request.terraformVersion())) {
            return evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED, List.of(RunnerReasonCode.TERRAFORM_VERSION_MISMATCH),
                    identity.runnerId(), observedSha256, approvalResult.reasonCode(), observedTerraformVersion, null);
        }
        String observedProviderLockHash = toolchainContext.observedProviderLockHash();
        if (!observedProviderLockHash.equals(request.providerLockHash())) {
            return evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED, List.of(RunnerReasonCode.PROVIDER_LOCK_HASH_MISMATCH),
                    identity.runnerId(), observedSha256, approvalResult.reasonCode(), observedTerraformVersion, observedProviderLockHash);
        }
        // state: CONTEXT_VERIFIED -> READY_FOR_FUTURE_EXECUTION

        return evidenceOf(request, startedAt, clock.instant(), RunnerState.READY_FOR_FUTURE_EXECUTION, List.of(),
                identity.runnerId(), observedSha256, approvalResult.reasonCode(), observedTerraformVersion, observedProviderLockHash);
    }

    private RunnerEvidence verifyContext(RunnerRequest request, Instant startedAt, String runnerId, ApprovalValidationReasonCode approvalReason) {
        String observedTerraformVersion = toolchainContext.observedTerraformVersion();
        if (!observedTerraformVersion.equals(request.terraformVersion())) {
            return evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED, List.of(RunnerReasonCode.TERRAFORM_VERSION_MISMATCH),
                    runnerId, null, approvalReason, observedTerraformVersion, null);
        }
        String observedProviderLockHash = toolchainContext.observedProviderLockHash();
        if (!observedProviderLockHash.equals(request.providerLockHash())) {
            return evidenceOf(request, startedAt, clock.instant(), RunnerState.BLOCKED, List.of(RunnerReasonCode.PROVIDER_LOCK_HASH_MISMATCH),
                    runnerId, null, approvalReason, observedTerraformVersion, observedProviderLockHash);
        }
        return evidenceOf(request, startedAt, clock.instant(), RunnerState.CONTEXT_VERIFIED, List.of(),
                runnerId, null, approvalReason, observedTerraformVersion, observedProviderLockHash);
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
            String runnerId, String observedPlanSha256, ApprovalValidationReasonCode approvalReason,
            String terraformVersionObserved, String providerLockHashObserved
    ) {
        return new RunnerEvidence(
                request.runnerRequestId(),
                runnerId,
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
