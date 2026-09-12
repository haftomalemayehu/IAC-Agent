package com.iacagent.iacagent.runner;

import java.time.Instant;
import java.util.List;

/**
 * The structured, per-attempt result of one {@code TERRAFORM_INIT} coordinator call - embedded as
 * {@link RunnerEvidence#terraformInitEvidence()}, exactly the same "embedded, not a separate ledger
 * row" pattern {@link TerraformProcessEvidence} established in Phase 2B-3.
 *
 * <p>Carries no raw stderr, and raw stdout only transiently at the coordinator layer - same
 * caution as {@link TerraformProcessEvidence} about not persisting tool output that could someday
 * contain sensitive content. Lockfile hashes are content hashes of {@code .terraform.lock.hcl}
 * itself (a small, non-secret, human-reviewable file - unlike provider/backend credentials, which
 * this phase never touches at all), not raw lockfile bytes.
 */
public record TerraformInitEvidence(
        String runnerRequestId,
        String runnerId,
        String configSha256,
        String executableSha256Expected,
        String executableSha256Observed,
        String terraformVersionExpected,
        String terraformVersionObserved,
        TerraformBackendMode backendMode,
        TerraformNetworkRequirement networkRequirement,
        List<String> providerSourcesRequested,
        List<String> moduleSourcesRequested,
        /** {@code null} if no {@code .terraform.lock.hcl} existed before {@code init} ran. */
        String lockfileHashBefore,
        /** {@code null} if no {@code .terraform.lock.hcl} exists after {@code init} ran (including
         * when {@code init} was never launched at all). */
        String lockfileHashAfter,
        Integer exitCode,
        boolean timedOut,
        TerraformProcessState processState,
        List<RunnerReasonCode> reasonCodes,
        long stdoutSize,
        long stderrSize,
        String stdoutSha256,
        String stderrSha256,
        Instant startedAt,
        Instant completedAt
) {
    public TerraformInitEvidence {
        if (processState == null) {
            throw new IllegalArgumentException("processState is required");
        }
        reasonCodes = reasonCodes == null ? List.of() : List.copyOf(reasonCodes);
        providerSourcesRequested = providerSourcesRequested == null ? List.of() : List.copyOf(providerSourcesRequested);
        moduleSourcesRequested = moduleSourcesRequested == null ? List.of() : List.copyOf(moduleSourcesRequested);
    }

    public boolean succeeded() {
        return processState == TerraformProcessState.SUCCEEDED;
    }
}
