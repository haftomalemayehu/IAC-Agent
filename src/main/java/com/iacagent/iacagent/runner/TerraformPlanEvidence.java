package com.iacagent.iacagent.runner;

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
        Instant completedAt
) {
    public TerraformPlanEvidence {
        if (processState == null) {
            throw new IllegalArgumentException("processState is required");
        }
        reasonCodes = reasonCodes == null ? List.of() : List.copyOf(reasonCodes);
    }

    public boolean hasChanges() {
        return processState == TerraformProcessState.COMMAND_REPORTED_DIFFERENCE;
    }

    public boolean succeeded() {
        return processState == TerraformProcessState.SUCCEEDED || processState == TerraformProcessState.COMMAND_REPORTED_DIFFERENCE;
    }
}
