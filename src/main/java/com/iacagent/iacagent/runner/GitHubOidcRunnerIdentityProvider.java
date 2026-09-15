package com.iacagent.iacagent.runner;

import com.iacagent.iacagent.identity.VerifiedWorkloadIdentity;
import com.iacagent.iacagent.identity.WorkloadIdentityTokenSource;
import com.iacagent.iacagent.identity.WorkloadIdentityTokenUnavailableException;
import com.iacagent.iacagent.identity.WorkloadIdentityVerificationResult;
import com.iacagent.iacagent.identity.WorkloadIdentityVerifier;

import java.util.Optional;
import java.util.Set;

/**
 * Phase 2B-7 production {@link RunnerIdentityProvider}: identity is a freshly minted, freshly
 * cryptographically verified GitHub Actions OIDC token - never a local file
 * ({@link HostAttestedRunnerIdentityProvider} remains reference/local-only), never a hostname,
 * never an environment variable asserting "I am runner X". A missing token, an unreachable
 * verifier, or a token that fails ANY verification check all collapse to {@link Optional#empty()} -
 * {@link ControlledRunner} already treats that as {@code RUNNER_IDENTITY_UNAVAILABLE} and blocks;
 * there is no fallback path here to anything less strict.
 *
 * <p>This provider answers only "is the ambient workload identity real, current, and trusted at
 * all" - the coarse-grained {@link RunnerIdentity#environmentScope()} it returns is fixed,
 * trusted, control-plane configuration (which environments THIS DEPLOYMENT of verified-OIDC
 * runners may generally act in), not derived from the token's own optional GitHub Environment
 * claim (many workflows never use that GitHub feature at all, so requiring it here would
 * incorrectly block them). The FINE-GRAINED binding - does the token's own repository/commit/
 * environment/workflow claims actually match THIS SPECIFIC execution request - is a separate,
 * deliberate policy decision made later, during credential federation, by
 * {@link FederatedTerraformCredentialProvider}/{@code WorkloadAuthorizationPolicy}, which (unlike
 * this interface) has access to the actual {@link RunnerRequest} being executed.
 *
 * <p>Verifies fresh on every call - never caches a prior verification result, matching the
 * "reflects changes on the next call without caching" discipline
 * {@link HostAttestedRunnerIdentityProvider} already established for this same interface.
 */
public final class GitHubOidcRunnerIdentityProvider implements RunnerIdentityProvider {

    private final WorkloadIdentityTokenSource tokenSource;
    private final WorkloadIdentityVerifier verifier;
    private final String audience;
    private final String runnerClass;
    private final Set<String> environmentScope;

    public GitHubOidcRunnerIdentityProvider(
            WorkloadIdentityTokenSource tokenSource, WorkloadIdentityVerifier verifier,
            String audience, String runnerClass, Set<String> environmentScope) {
        if (tokenSource == null) {
            throw new IllegalArgumentException("tokenSource is required");
        }
        if (verifier == null) {
            throw new IllegalArgumentException("verifier is required");
        }
        if (audience == null || audience.isBlank()) {
            throw new IllegalArgumentException("audience is required");
        }
        if (runnerClass == null || runnerClass.isBlank()) {
            throw new IllegalArgumentException("runnerClass is required");
        }
        this.tokenSource = tokenSource;
        this.verifier = verifier;
        this.audience = audience;
        this.runnerClass = runnerClass;
        this.environmentScope = environmentScope == null ? Set.of() : Set.copyOf(environmentScope);
    }

    @Override
    public Optional<RunnerIdentity> currentIdentity() {
        String rawToken;
        try {
            rawToken = tokenSource.currentToken(audience);
        } catch (WorkloadIdentityTokenUnavailableException e) {
            return Optional.empty();
        }
        WorkloadIdentityVerificationResult result = verifier.verify(rawToken);
        if (!result.isValid()) {
            return Optional.empty();
        }
        VerifiedWorkloadIdentity identity = result.identity();
        String runnerId = "github-oidc:" + identity.subjectSha256();
        return Optional.of(new RunnerIdentity(runnerId, runnerClass, environmentScope, true));
    }
}
