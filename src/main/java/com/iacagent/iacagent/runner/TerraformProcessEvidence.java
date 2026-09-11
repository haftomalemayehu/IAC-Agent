package com.iacagent.iacagent.runner;

import java.time.Instant;
import java.util.List;

/**
 * The structured, per-attempt result of one Terraform process-boundary operation. Embedded as
 * {@link RunnerEvidence#terraformProcessEvidence()} rather than persisted as a wholly separate
 * ledger row - {@code runnerRequestId}/{@code repository}/{@code commitSha}/{@code environment}/
 * {@code planSha256}/{@code runnerId} linkage (per the Phase 2B-3 design doc's requirement) is
 * therefore structural (this record lives inside the {@link RunnerEvidence} that already carries
 * all of those) rather than duplicated here field-for-field; {@code runnerRequestId}/{@code runnerId}
 * are still carried directly so this record remains self-describing if ever extracted or serialized
 * independently (see {@code JdbcRunnerLedgerRepository}'s {@code terraform_process_evidence} column).
 *
 * <p>Deliberately does not carry raw stderr bytes, and carries raw stdout only transiently at the
 * {@link ControlledTerraformProcess}/{@link ControlledTerraformOperationCoordinator} layer, never
 * here - only sizes and hashes, per the design doc's caution that Terraform/provider tooling output
 * could someday contain sensitive content.
 */
public record TerraformProcessEvidence(
        String runnerRequestId,
        String runnerId,
        ControlledTerraformOperation operation,
        String executablePathIdentity,
        String executableSha256Expected,
        String executableSha256Observed,
        String terraformVersionExpected,
        String terraformVersionObserved,
        String workingDirectoryIdentity,
        String planSha256Expected,
        String planSha256Observed,
        String argvTemplateId,
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
    public TerraformProcessEvidence {
        if (processState == null) {
            throw new IllegalArgumentException("processState is required");
        }
        reasonCodes = reasonCodes == null ? List.of() : List.copyOf(reasonCodes);
    }
}
