package com.iacagent.iacagent.identity;

/**
 * Verifies a bearer workload-identity token (a JWT in every implementation this codebase ships) and
 * produces a {@link VerifiedWorkloadIdentity} containing ONLY claims that survived full cryptographic
 * and policy verification. Implementations must verify, at minimum: signature (against a trusted,
 * never caller-selected key source), issuer (pinned, never caller-selected), audience (pinned, never
 * caller-selected), expiration, not-before (if present), issued-at sanity, presence of every claim
 * this verifier's {@link VerifiedWorkloadIdentity} construction requires, and signing algorithm
 * (a fixed allowlist - {@code alg=none} and any algorithm outside the allowlist are always rejected
 * before signature verification is even attempted).
 *
 * <p>{@code rawToken} is treated as a bearer secret by every implementation: it must never be logged,
 * persisted, or echoed into any exception message or evidence record - only the resulting
 * {@link VerifiedWorkloadIdentity}'s non-secret fields (or a {@link com.iacagent.iacagent.runner.RunnerReasonCode}
 * on failure) may ever leave this boundary.
 */
public interface WorkloadIdentityVerifier {
    WorkloadIdentityVerificationResult verify(String rawToken);
}
