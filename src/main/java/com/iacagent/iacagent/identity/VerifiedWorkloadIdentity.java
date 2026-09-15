package com.iacagent.iacagent.identity;

import java.time.Instant;

/**
 * A workload's identity, established EXCLUSIVELY from claims a {@link WorkloadIdentityVerifier} has
 * cryptographically verified - never from a {@link com.iacagent.iacagent.runner.RunnerRequest} field,
 * repository content, or any other caller-supplied value. There is deliberately no constructor path
 * that lets a caller hand this class pre-built claims without going through verification first - the
 * only producer of instances of this type in this codebase is {@link WorkloadIdentityVerifier#verify}.
 *
 * <p>Request values (e.g. {@code request.repository()}) may be COMPARED against these fields (see
 * {@link WorkloadAuthorizationPolicy#authorize}) but must never be used to construct one - a request
 * cannot make itself "more trusted" by simply claiming the same values a verified token happens to
 * carry.
 *
 * <p>{@code subjectSha256} is a non-secret SHA-256 hash of the token's raw {@code sub} claim, not the
 * claim itself - {@code sub} for GitHub Actions OIDC is not secret, but hashing it here keeps this
 * record safe to embed directly into audit evidence without a second thought about what it might
 * reveal, and keeps this type's own {@code toString()} inherently non-sensitive.
 */
public record VerifiedWorkloadIdentity(
        String issuer,
        String subjectSha256,
        String audience,
        String repository,
        String repositoryOwner,
        String ref,
        String commitSha,
        String workflowRef,
        String environment,
        Instant issuedAt,
        Instant expiresAt,
        String tokenIdSha256
) {
    public VerifiedWorkloadIdentity {
        require(issuer, "issuer");
        require(subjectSha256, "subjectSha256");
        require(audience, "audience");
        require(repository, "repository");
        require(repositoryOwner, "repositoryOwner");
        require(commitSha, "commitSha");
        require(workflowRef, "workflowRef");
        if (issuedAt == null) {
            throw new IllegalArgumentException("issuedAt is required");
        }
        if (expiresAt == null) {
            throw new IllegalArgumentException("expiresAt is required");
        }
        // ref/environment/tokenIdSha256 are legitimately nullable - a workflow token may lack a
        // GitHub Environment claim entirely, and not every issuer exposes a usable jti.
    }

    private static void require(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
    }
}
