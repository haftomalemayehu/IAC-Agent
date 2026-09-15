package com.iacagent.iacagent.runner;

import com.iacagent.iacagent.identity.WorkloadIdentityEvidence;

import java.time.Instant;
import java.util.List;

/**
 * The structured, per-attempt result of one {@code TERRAFORM_PLAN} coordinator call - embedded as
 * {@link RunnerEvidence#terraformPlanEvidence()}, the same "embedded, not a separate ledger row"
 * pattern established for every other Terraform operation's evidence in this package.
 *
 * <p>Deliberately carries no credential material anywhere (only {@code credentialSourceIdentifier},
 * a non-secret label - see {@link TerraformCredentialMaterial}), no raw stderr, and raw stdout only
 * transiently at the coordinator layer - same discipline as every other Terraform evidence record
 * in this package.
 *
 * <p>{@code workloadIdentityEvidence} (Phase 2B-7) is attached via {@link #withWorkloadIdentityEvidence}
 * rather than threaded through the coordinator's existing internal evidence-construction helper -
 * deliberately, to avoid touching that helper's already-large parameter list and its many existing
 * call sites for a concern that only ever applies from the point credential resolution is attempted
 * onward. {@code null} for every outcome that never reached credential resolution at all (e.g. a
 * config/backend-policy block before {@code init} ever runs).
 */
public record TerraformPlanEvidence(
        String runnerRequestId,
        String runnerId,
        String repository,
        String commitSha,
        String environment,
        String configSha256,
        String stateIdentitySha256,
        String planInputSha256,
        String executableSha256Expected,
        String executableSha256Observed,
        String terraformVersionExpected,
        String terraformVersionObserved,
        String providerLockHash,
        String backendType,
        String backendInstanceId,
        String credentialSourceIdentifier,
        String planArtifactId,
        String planSha256,
        long planByteSize,
        String showJsonSha256,
        long showJsonByteSize,
        Integer createCount,
        Integer updateCount,
        Integer replaceCount,
        Integer destroyCount,
        Integer exitCode,
        boolean timedOut,
        TerraformProcessState processState,
        List<RunnerReasonCode> reasonCodes,
        Instant startedAt,
        Instant completedAt,
        WorkloadIdentityEvidence workloadIdentityEvidence
) {
    public TerraformPlanEvidence {
        if (processState == null) {
            throw new IllegalArgumentException("processState is required");
        }
        reasonCodes = reasonCodes == null ? List.of() : List.copyOf(reasonCodes);
    }

    /** Convenience constructor for every pre-2B-7 call site - {@code workloadIdentityEvidence} is
     * always {@code null}. */
    public TerraformPlanEvidence(
            String runnerRequestId, String runnerId, String repository, String commitSha, String environment,
            String configSha256, String stateIdentitySha256, String planInputSha256,
            String executableSha256Expected, String executableSha256Observed,
            String terraformVersionExpected, String terraformVersionObserved,
            String providerLockHash, String backendType, String backendInstanceId, String credentialSourceIdentifier,
            String planArtifactId, String planSha256, long planByteSize, String showJsonSha256, long showJsonByteSize,
            Integer createCount, Integer updateCount, Integer replaceCount, Integer destroyCount,
            Integer exitCode, boolean timedOut, TerraformProcessState processState, List<RunnerReasonCode> reasonCodes,
            Instant startedAt, Instant completedAt
    ) {
        this(runnerRequestId, runnerId, repository, commitSha, environment, configSha256, stateIdentitySha256, planInputSha256,
                executableSha256Expected, executableSha256Observed, terraformVersionExpected, terraformVersionObserved,
                providerLockHash, backendType, backendInstanceId, credentialSourceIdentifier,
                planArtifactId, planSha256, planByteSize, showJsonSha256, showJsonByteSize,
                createCount, updateCount, replaceCount, destroyCount,
                exitCode, timedOut, processState, reasonCodes, startedAt, completedAt, null);
    }

    public boolean hasChanges() {
        return processState == TerraformProcessState.COMMAND_REPORTED_DIFFERENCE;
    }

    public boolean succeeded() {
        return processState == TerraformProcessState.SUCCEEDED || processState == TerraformProcessState.COMMAND_REPORTED_DIFFERENCE;
    }

    /** Returns a copy with {@code workloadIdentityEvidence} attached - see the class javadoc for
     * why this is a post-construction wither rather than a threaded-through parameter. */
    public TerraformPlanEvidence withWorkloadIdentityEvidence(WorkloadIdentityEvidence evidence) {
        return new TerraformPlanEvidence(
                runnerRequestId, runnerId, repository, commitSha, environment, configSha256, stateIdentitySha256, planInputSha256,
                executableSha256Expected, executableSha256Observed, terraformVersionExpected, terraformVersionObserved,
                providerLockHash, backendType, backendInstanceId, credentialSourceIdentifier,
                planArtifactId, planSha256, planByteSize, showJsonSha256, showJsonByteSize,
                createCount, updateCount, replaceCount, destroyCount,
                exitCode, timedOut, processState, reasonCodes, startedAt, completedAt, evidence);
    }
}
