package com.iacagent.iacagent.runner;

import java.time.Instant;

/** Everything about a stored saved-plan artifact EXCEPT its bytes - what the same
 * {@code ApprovalRecord}/{@code ExecutionIdentity} binding used elsewhere in this codebase needs to
 * resolve/verify a plan by id without necessarily loading the full binary. */
public record TerraformPlanArtifactMetadata(
        String planArtifactId,
        String planSha256,
        String planInputSha256,
        String repository,
        String commitSha,
        String environment,
        String stateIdentitySha256,
        long planByteSize,
        Instant storedAt
) {
    public TerraformPlanArtifactMetadata {
        require(planArtifactId, "planArtifactId");
        require(planSha256, "planSha256");
        require(planInputSha256, "planInputSha256");
        require(repository, "repository");
        require(commitSha, "commitSha");
        require(environment, "environment");
        require(stateIdentitySha256, "stateIdentitySha256");
        if (storedAt == null) {
            throw new IllegalArgumentException("storedAt is required");
        }
    }

    private static void require(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
    }
}
