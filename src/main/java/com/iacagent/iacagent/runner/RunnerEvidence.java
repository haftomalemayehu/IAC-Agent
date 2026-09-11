package com.iacagent.iacagent.runner;

import com.iacagent.iacagent.approval.ApprovalValidationReasonCode;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * The structured, append-only result of one runner attempt. Every {@link ControlledRunner#execute}
 * call produces exactly one of these - for every outcome, not just success. Fields whose value
 * was never observed (e.g. {@code observedPlanSha256} when the request BLOCKED before the
 * artifact was ever resolved, or {@code runnerId}/{@code runnerClass}/{@code runnerEnvironmentScope}
 * when it BLOCKED before identity was ever resolved) are {@code null} or empty, not a placeholder
 * value.
 *
 * <p>Deliberately excludes anything resembling raw environment variables, credentials, or secret
 * material - there is no field here for "environment dump" because {@link ControlledRunner} never
 * captures one in the first place, per the isolation model in the Phase 2B-1/2B-2 design docs.
 */
public record RunnerEvidence(
        String runnerRequestId,
        String runnerId,
        String runnerClass,
        Set<String> runnerEnvironmentScope,
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
        runnerEnvironmentScope = runnerEnvironmentScope == null ? Set.of() : Set.copyOf(runnerEnvironmentScope);
    }

    public boolean isReadyForFutureExecution() {
        return finalState == RunnerState.READY_FOR_FUTURE_EXECUTION;
    }
}
