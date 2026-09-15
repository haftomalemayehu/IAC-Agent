package com.iacagent.iacagent.identity;

import com.iacagent.iacagent.runner.RunnerReasonCode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 2B-7 Gate C real-issuer acceptance: mints a REAL GitHub Actions OIDC token (via the ambient
 * {@code ACTIONS_ID_TOKEN_REQUEST_URL}/{@code ACTIONS_ID_TOKEN_REQUEST_TOKEN} the Actions runtime
 * populates for a job with {@code id-token: write} permission) and verifies it against the REAL
 * {@code https://token.actions.githubusercontent.com} issuer/JWKS - no mock, no fake JWKS server,
 * no locally-signed token anywhere in this class.
 *
 * <p>Only meaningful inside an actual GitHub Actions job - {@code @EnabledIfEnvironmentVariable}
 * makes this auto-skip (not fail) everywhere else, including a plain local {@code ./gradlew test}
 * run, so this suite's absence of evidence is never silently reported as a pass.
 *
 * <p>Run via {@code ./gradlew identityAcceptanceTest} - see
 * {@code .github/workflows/phase2b7-identity-acceptance.yml} for the actual invoking workflow.
 * Never prints the raw token - only sanitized, already-non-secret verified claims.
 */
@EnabledIfEnvironmentVariable(named = "ACTIONS_ID_TOKEN_REQUEST_URL", matches = ".+")
class RealGitHubActionsOidcAcceptanceTest {

    private static String audience() {
        String override = System.getenv("IAC_AGENT_TEST_AUDIENCE");
        return override == null || override.isBlank() ? "sts.amazonaws.com" : override;
    }

    @Test
    void realGitHubIssuedTokenVerifiesAgainstTheRealIssuerAndJwks() {
        String audience = audience();
        String token = new GitHubActionsIdTokenSource().currentToken(audience);
        assertNotNull(token);

        GitHubActionsOidcVerifier verifier = new GitHubActionsOidcVerifier(WorkloadIdentityVerifierConfig.githubActionsDefaults(audience));
        WorkloadIdentityVerificationResult result = verifier.verify(token);

        assertTrue(result.isValid(), () -> "expected a valid real GitHub Actions OIDC token, got failure: " + result.failureReason());
        VerifiedWorkloadIdentity identity = result.identity();

        String expectedRepository = System.getenv("GITHUB_REPOSITORY");
        assertNotNull(expectedRepository, "GITHUB_REPOSITORY must be set inside a real GitHub Actions job");
        assertEquals(expectedRepository, identity.repository());
        assertEquals("https://token.actions.githubusercontent.com", identity.issuer());
        assertEquals(audience, identity.audience());
        assertNotNull(identity.commitSha());
        assertNotNull(identity.workflowRef());

        // Sanitized only - never the raw token, never anything beyond already-non-secret claims.
        System.out.println("[Phase2b7 real-oidc-acceptance] issuer=" + identity.issuer()
                + " audience=" + identity.audience()
                + " repository=" + identity.repository()
                + " repositoryOwner=" + identity.repositoryOwner()
                + " workflowRef=" + identity.workflowRef()
                + " commitShaPrefix=" + identity.commitSha().substring(0, 8)
                + " expiresAt=" + identity.expiresAt());
    }

    @Test
    void realTokenIsRejectedWhenVerifiedAgainstAWrongAudience() {
        String realAudience = audience();
        String token = new GitHubActionsIdTokenSource().currentToken(realAudience);

        GitHubActionsOidcVerifier verifier = new GitHubActionsOidcVerifier(
                WorkloadIdentityVerifierConfig.githubActionsDefaults("a-completely-different-audience-" + System.nanoTime()));
        WorkloadIdentityVerificationResult result = verifier.verify(token);

        assertFalse(result.isValid());
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_AUDIENCE_MISMATCH, result.failureReason());
        System.out.println("[Phase2b7 real-oidc-acceptance] wrong-audience rejection confirmed: " + result.failureReason());
    }

    @Test
    void realVerifiedIdentityIsDeniedByAuthorizationPolicyWhenExecutionIdentityDoesNotMatch() {
        // A fully valid, REAL, cryptographically verified token - but the authorization step must
        // still independently deny it when the execution identity it's being checked against
        // doesn't match. This is the "a token merely originating from GitHub Actions is not
        // sufficient" property, proven against a real token rather than a locally-signed one.
        String audience = audience();
        String token = new GitHubActionsIdTokenSource().currentToken(audience);
        WorkloadIdentityVerificationResult result = new GitHubActionsOidcVerifier(WorkloadIdentityVerifierConfig.githubActionsDefaults(audience)).verify(token);
        assertTrue(result.isValid(), () -> "expected a valid real token for this sub-test too, got: " + result.failureReason());
        VerifiedWorkloadIdentity identity = result.identity();

        // Case 1: repository mismatch - authorize for a DIFFERENT repository than the token proves.
        var repoMismatchPolicy = new TrustedWorkloadAuthorizationPolicy(java.util.Set.of(
                new AllowedWorkload("someone-else/unrelated-repo", identity.repositoryOwner(), "nonprod", identity.workflowRef())));
        var repoResult = repoMismatchPolicy.authorize(identity, "someone-else/unrelated-repo", identity.commitSha(), "nonprod");
        assertFalse(repoResult.authorized());
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_REPOSITORY_MISMATCH, repoResult.failureReason());

        // Case 2: no rule at all for this repository/environment pair (workflow-not-authorized).
        var noRulePolicy = new TrustedWorkloadAuthorizationPolicy(java.util.Set.of());
        var noRuleResult = noRulePolicy.authorize(identity, identity.repository(), identity.commitSha(), "nonprod");
        assertFalse(noRuleResult.authorized());
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_WORKFLOW_NOT_AUTHORIZED, noRuleResult.failureReason());

        // Case 3: matching rule DOES grant authorization for the real, correct binding.
        var matchingPolicy = new TrustedWorkloadAuthorizationPolicy(java.util.Set.of(
                new AllowedWorkload(identity.repository(), identity.repositoryOwner(), "nonprod", identity.workflowRef())));
        var matchingResult = matchingPolicy.authorize(identity, identity.repository(), identity.commitSha(), "nonprod");
        assertTrue(matchingResult.authorized(), () -> "expected the matching rule to grant authorization, got: " + matchingResult.failureReason());

        System.out.println("[Phase2b7 real-oidc-acceptance] policy/binding checks against a real token: "
                + "repositoryMismatch=" + repoResult.failureReason()
                + " noAuthorizedWorkflow=" + noRuleResult.failureReason()
                + " matchingRuleGranted=" + matchingResult.authorized());
    }
}
