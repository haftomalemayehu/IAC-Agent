package com.iacagent.iacagent.runner;

import java.time.Instant;
import java.util.List;

/**
 * The structured result of one {@code TERRAFORM_VALIDATE} coordinator call. {@code initEvidence} is
 * the SAME internally-run {@code TERRAFORM_INIT} attempt's evidence that gated this validate
 * attempt - embedding it (rather than a separate cross-request lookup key) is what makes "validate
 * evidence bound to init/config" trivially true: it is structurally the same object, produced in
 * the same {@link ControlledTerraformOperationCoordinator#executeValidate} call, for the identical
 * {@code configSha256}. {@code initEvidence} is non-null even when it failed (its own
 * {@code processState}/{@code reasonCodes} explain why validate never ran its own command).
 *
 * <p>{@code diagnosticFingerprints} deliberately does not carry raw diagnostic text (which may
 * reference repository file paths or configuration content) - each fingerprint is a SHA-256 over a
 * diagnostic's severity+summary+detail, letting evidence consumers detect "the same diagnostic
 * reappeared" or "diagnostics changed" without persisting the diagnostic content itself.
 */
public record TerraformValidateEvidence(
        String runnerRequestId,
        String runnerId,
        TerraformInitEvidence initEvidence,
        String configSha256,
        Boolean valid,
        Integer errorCount,
        Integer warningCount,
        List<String> diagnosticFingerprints,
        Integer exitCode,
        boolean timedOut,
        TerraformProcessState processState,
        List<RunnerReasonCode> reasonCodes,
        String stdoutSha256,
        Instant startedAt,
        Instant completedAt
) {
    public TerraformValidateEvidence {
        if (initEvidence == null) {
            throw new IllegalArgumentException("initEvidence is required - validate never runs without an init attempt of some outcome");
        }
        if (processState == null) {
            throw new IllegalArgumentException("processState is required");
        }
        reasonCodes = reasonCodes == null ? List.of() : List.copyOf(reasonCodes);
        diagnosticFingerprints = diagnosticFingerprints == null ? List.of() : List.copyOf(diagnosticFingerprints);
    }
}
