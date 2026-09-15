package com.iacagent.iacagent.identity;

/**
 * Obtains a fresh bearer workload-identity token for THIS execution context - never from a
 * {@link com.iacagent.iacagent.runner.RunnerRequest} field, always ambient (e.g. the CI/CD platform's
 * own OIDC-minting endpoint). The returned token is treated as a bearer secret by every caller: it
 * must be handed directly to a {@link WorkloadIdentityVerifier} and never logged, persisted, or
 * placed in any exception message beyond this boundary.
 */
public interface WorkloadIdentityTokenSource {
    /** Mints/fetches a token scoped to {@code audience}. Implementations must never cache the
     * result beyond the immediate call - each call may (and for GitHub Actions, does) mint a fresh
     * token. Throws {@link WorkloadIdentityTokenUnavailableException} if no token could be
     * obtained. */
    String currentToken(String audience);
}
