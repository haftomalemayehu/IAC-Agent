package com.iacagent.iacagent.approval;

/**
 * The identity of the infrastructure change an approval authorizes or an execution request
 * targets, per docs/phase-2a-execution-contract.md SS1: repository + commitSha + environment +
 * planSha256. Two requests with the same ExecutionIdentity are requests for the same change;
 * this type intentionally excludes requestId/approvalId, which are attempt/reference identifiers,
 * not authorization identity.
 */
public record ExecutionIdentity(
        String repository,
        String commitSha,
        String environment,
        String planSha256
) {
    public ExecutionIdentity {
        if (repository == null || repository.isBlank()) {
            throw new IllegalArgumentException("repository is required");
        }
        if (commitSha == null || commitSha.isBlank()) {
            throw new IllegalArgumentException("commitSha is required");
        }
        if (environment == null || environment.isBlank()) {
            throw new IllegalArgumentException("environment is required");
        }
        if (planSha256 == null || planSha256.isBlank()) {
            throw new IllegalArgumentException("planSha256 is required");
        }
    }
}
