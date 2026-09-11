package com.iacagent.iacagent.runner;

/**
 * The typed, caller-supplied request contract. Deliberately carries no runner-identity field of
 * any kind (no runnerId, no "trusted" flag, no environment-scope claim) - identity is resolved
 * exclusively from {@link RunnerIdentityProvider}, a dependency of {@link ControlledRunner} that
 * the caller cannot reach or influence. A caller who wants to see this enforced can inspect this
 * type's record components directly: there is nothing to spoof because there is nowhere to put it.
 *
 * <p>Also carries no raw command/shell string - {@code requestedOperation} is the closed
 * {@link RunnerOperation} enum, not free text, and no field here is ever interpreted as an
 * executable, an argument list, or a URL to fetch.
 */
public record RunnerRequest(
        String runnerRequestId,
        String repository,
        String commitSha,
        String environment,
        String planArtifactId,
        String planSha256,
        String terraformVersion,
        String providerLockHash,
        String approvalId,
        RunnerOperation requestedOperation
) {
    public RunnerRequest {
        require(runnerRequestId, "runnerRequestId");
        require(repository, "repository");
        require(commitSha, "commitSha");
        require(environment, "environment");
        require(planArtifactId, "planArtifactId");
        require(planSha256, "planSha256");
        require(terraformVersion, "terraformVersion");
        require(providerLockHash, "providerLockHash");
        require(approvalId, "approvalId");
        if (requestedOperation == null) {
            throw new IllegalArgumentException("requestedOperation is required");
        }
    }

    private static void require(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
    }
}
