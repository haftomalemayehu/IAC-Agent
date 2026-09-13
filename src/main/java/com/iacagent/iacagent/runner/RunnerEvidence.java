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
        Instant completedAt,
        TerraformProcessEvidence terraformProcessEvidence,
        TerraformInitEvidence terraformInitEvidence,
        TerraformValidateEvidence terraformValidateEvidence,
        TerraformProviderSchemaEvidence terraformProviderSchemaEvidence,
        TerraformPlanEvidence terraformPlanEvidence
) {
    public RunnerEvidence {
        reasonCodes = reasonCodes == null ? List.of() : List.copyOf(reasonCodes);
        runnerEnvironmentScope = runnerEnvironmentScope == null ? Set.of() : Set.copyOf(runnerEnvironmentScope);
        // terraformProcessEvidence is deliberately nullable - non-null only for the Phase 2B-3
        // TERRAFORM_VERSION/TERRAFORM_FMT_CHECK/TERRAFORM_SHOW_PLAN_JSON operations; every
        // pre-2B-3 operation (and any 2B-3 attempt that BLOCKED before a Terraform process was ever
        // attempted) carries null here, same as observedPlanSha256 etc. being null before their
        // corresponding check ever ran.
        //
        // Phase 2B-4 adds three more, same discipline: terraformInitEvidence is non-null only for
        // TERRAFORM_INIT; terraformValidateEvidence/terraformProviderSchemaEvidence are non-null
        // only for TERRAFORM_VALIDATE/TERRAFORM_PROVIDERS_SCHEMA respectively (each of which
        // embeds its own internally-run init attempt's TerraformInitEvidence, so it is never
        // duplicated into this record's own terraformInitEvidence field as well).
        //
        // Phase 2B-5 adds terraformPlanEvidence, non-null only for TERRAFORM_PLAN. Exactly one of
        // these five Terraform evidence fields is ever non-null for a given RunnerEvidence.
    }

    /** Convenience constructor for every operation before Phase 2B-4 - the four new evidence
     * fields are always null. */
    public RunnerEvidence(
            String runnerRequestId, String runnerId, String runnerClass, Set<String> runnerEnvironmentScope, RunnerOperation operation,
            String repository, String commitSha, String environment, String planArtifactId, String expectedPlanSha256, String observedPlanSha256,
            String terraformVersionExpected, String terraformVersionObserved, String providerLockHashExpected, String providerLockHashObserved,
            String approvalId, ApprovalValidationReasonCode approvalValidationResult, RunnerState finalState, List<RunnerReasonCode> reasonCodes,
            Instant startedAt, Instant completedAt, TerraformProcessEvidence terraformProcessEvidence
    ) {
        this(runnerRequestId, runnerId, runnerClass, runnerEnvironmentScope, operation, repository, commitSha, environment, planArtifactId,
                expectedPlanSha256, observedPlanSha256, terraformVersionExpected, terraformVersionObserved, providerLockHashExpected,
                providerLockHashObserved, approvalId, approvalValidationResult, finalState, reasonCodes, startedAt, completedAt,
                terraformProcessEvidence, null, null, null, null);
    }

    /** Convenience constructor for Phase 2B-4 operations (init/validate/providers-schema) - the new
     * Phase 2B-5 plan-evidence field is always null. */
    public RunnerEvidence(
            String runnerRequestId, String runnerId, String runnerClass, Set<String> runnerEnvironmentScope, RunnerOperation operation,
            String repository, String commitSha, String environment, String planArtifactId, String expectedPlanSha256, String observedPlanSha256,
            String terraformVersionExpected, String terraformVersionObserved, String providerLockHashExpected, String providerLockHashObserved,
            String approvalId, ApprovalValidationReasonCode approvalValidationResult, RunnerState finalState, List<RunnerReasonCode> reasonCodes,
            Instant startedAt, Instant completedAt, TerraformProcessEvidence terraformProcessEvidence, TerraformInitEvidence terraformInitEvidence,
            TerraformValidateEvidence terraformValidateEvidence, TerraformProviderSchemaEvidence terraformProviderSchemaEvidence
    ) {
        this(runnerRequestId, runnerId, runnerClass, runnerEnvironmentScope, operation, repository, commitSha, environment, planArtifactId,
                expectedPlanSha256, observedPlanSha256, terraformVersionExpected, terraformVersionObserved, providerLockHashExpected,
                providerLockHashObserved, approvalId, approvalValidationResult, finalState, reasonCodes, startedAt, completedAt,
                terraformProcessEvidence, terraformInitEvidence, terraformValidateEvidence, terraformProviderSchemaEvidence, null);
    }

    public boolean isReadyForFutureExecution() {
        return finalState == RunnerState.READY_FOR_FUTURE_EXECUTION;
    }

    public boolean isTerraformProcessCompleted() {
        return finalState == RunnerState.TERRAFORM_PROCESS_COMPLETED;
    }
}
