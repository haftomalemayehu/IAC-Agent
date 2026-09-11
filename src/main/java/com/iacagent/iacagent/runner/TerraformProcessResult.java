package com.iacagent.iacagent.runner;

import java.time.Instant;

/**
 * The raw result of one {@link ControlledTerraformProcess#execute} call - deliberately carries no
 * operation-specific interpretation (JSON parsing, version comparison, exit-code-to-outcome mapping)
 * of its own; {@link ControlledTerraformOperationCoordinator} is what turns this, plus knowledge of
 * WHICH operation ran, into a final {@link TerraformProcessState}. Exactly one of
 * {@code startFailed}/{@code timedOut}/{@code outputLimitExceeded} may be true, or none of them (a
 * normal exit, with {@code exitCode} populated, left for the caller to interpret).
 *
 * <p>{@code stdout} carries the actual bounded bytes captured (needed by the caller to parse
 * structured output); stderr is deliberately NOT carried as raw bytes here - only its size and hash
 * - per the Phase 2B-3 design doc's caution about not persisting arbitrary process/tool output that
 * could someday contain sensitive content.
 */
public record TerraformProcessResult(
        boolean startFailed,
        boolean timedOut,
        boolean outputLimitExceeded,
        Integer exitCode,
        byte[] stdout,
        long stdoutSize,
        String stdoutSha256,
        long stderrSize,
        String stderrSha256,
        Instant startedAt,
        Instant completedAt
) {
    public TerraformProcessResult {
        stdout = stdout == null ? new byte[0] : stdout.clone();
        if (startedAt == null) {
            throw new IllegalArgumentException("startedAt is required");
        }
        if (completedAt == null) {
            throw new IllegalArgumentException("completedAt is required");
        }
        int terminalOutcomes = (startFailed ? 1 : 0) + (timedOut ? 1 : 0) + (outputLimitExceeded ? 1 : 0);
        if (terminalOutcomes > 1) {
            throw new IllegalArgumentException("at most one of startFailed/timedOut/outputLimitExceeded may be true");
        }
        if (terminalOutcomes == 0 && exitCode == null) {
            throw new IllegalArgumentException("exitCode is required when the process neither failed to start, timed out, nor exceeded its output limit");
        }
    }

    @Override
    public byte[] stdout() {
        return stdout.clone();
    }
}
