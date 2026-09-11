package com.iacagent.iacagent.runner;

import com.iacagent.iacagent.approval.ApprovalValidationReasonCode;

import java.time.Instant;
import java.util.List;

/**
 * The structured, append-only result of one runner attempt. Every {@link ControlledRunner#execute}
 * call produces exactly one of these - for every outcome, not just success. Fields whose value
 * was never observed (e.g. {@code observedPlanSha256} when the request BLOCKED before the
 * artifact was ever resolved) are {@code null}, not a placeholder value.
 *
 * <p>Deliberately excludes anything resembling raw environment variables, credentials, or secret
 * material - there is no field here for "environment dump" because {@link ControlledRunner} never
 * captures one in the first place, per the isolation model in the Phase 2B-1 design doc.
 */
public record RunnerEvidence(
        String runnerRequestId,
        String runnerId,
        RunnerOperation operation,
        String repository,
        String commitSha,
        String environment,
        String planArtifactId,
        String expectedPlanSha256,
        String observedPlanSha256,
        String terraformVersionExpected,
        String terraformVersionObserved,
        String providerLockHashExpected,
        String providerLockHashObserved,
        String approvalId,
        ApprovalValidationReasonCode approvalValidationResult,
        RunnerState finalState,
        List<RunnerReasonCode> reasonCodes,
        Instant startedAt,
        Instant completedAt
) {
    public RunnerEvidence {
        reasonCodes = reasonCodes == null ? List.of() : List.copyOf(reasonCodes);
    }

    public boolean isReadyForFutureExecution() {
        return finalState == RunnerState.READY_FOR_FUTURE_EXECUTION;
    }
}
