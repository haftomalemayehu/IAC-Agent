package com.iacagent.iacagent.identity;

/**
 * Establishes that a {@link VerifiedWorkloadIdentity} - already cryptographically verified by
 * {@link WorkloadIdentityVerifier} - is permitted to act for a SPECIFIC execution identity
 * (repository/commit/environment). A token merely originating from a trusted issuer is never, by
 * itself, sufficient: this is the separate, deliberate policy decision the authorization docs
 * require ("A token merely originating from GitHub Actions is not sufficient").
 */
public interface WorkloadAuthorizationPolicy {
    WorkloadAuthorizationResult authorize(VerifiedWorkloadIdentity identity, String repository, String commitSha, String environment);
}
