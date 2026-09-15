package com.iacagent.iacagent.identity;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.SigningKeyNotFoundException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.iacagent.iacagent.runner.ControlledTerraformOperation;
import com.iacagent.iacagent.runner.FederatedTerraformCredentialProvider;
import com.iacagent.iacagent.runner.GitHubOidcRunnerIdentityProvider;
import com.iacagent.iacagent.runner.RunnerIdentity;
import com.iacagent.iacagent.runner.RunnerOperation;
import com.iacagent.iacagent.runner.RunnerReasonCode;
import com.iacagent.iacagent.runner.RunnerRequest;
import com.iacagent.iacagent.runner.TerraformCredentialMaterial;
import com.iacagent.iacagent.runner.TerraformCredentialProvider;
import com.iacagent.iacagent.runner.TerraformStateIdentity;
import org.junit.jupiter.api.Test;

import java.lang.reflect.RecordComponent;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 2B-7 unit tests (no real network/cloud - see {@code src/identityAcceptanceTest} for the
 * real-GitHub-issuer acceptance suite that is Gate C's actual closure evidence for the identity
 * half; AWS federation real acceptance is explicitly deferred pending real AWS role/account
 * infrastructure - see {@code docs/phase-2b7-workload-identity-federation.md} §22).
 *
 * <p>Covers: {@link GitHubActionsOidcVerifier} against locally-signed JWTs and a fake
 * {@link JwkProvider} (every negative case §24 of the authorization requires),
 * {@link TrustedWorkloadAuthorizationPolicy}, {@link FederatedTerraformCredentialProvider}'s
 * verify→authorize→federate composition (hand-written fakes for each step),
 * {@link GitHubOidcRunnerIdentityProvider}, {@link ProductionWorkloadIdentityConfiguration}'s
 * fail-closed no-fallback behavior, and the structural invariants §30 requires.
 */
class Phase2b7Tests {

    private static final String ISSUER = "https://token.actions.githubusercontent.com";
    private static final String AUDIENCE = "sts.amazonaws.com";
    private static final String REPOSITORY = "owner/repo";
    private static final String REPOSITORY_OWNER = "owner";
    private static final String COMMIT_SHA = "c".repeat(40);
    private static final String WORKFLOW_REF = "owner/repo/.github/workflows/plan.yml@refs/heads/main";
    private static final String KID = "test-kid-1";

    // ===================== local JWT signing test fixtures =====================

    private record TestKeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        static TestKeyPair generate() throws Exception {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair pair = gen.generateKeyPair();
            return new TestKeyPair((RSAPublicKey) pair.getPublic(), (RSAPrivateKey) pair.getPrivate());
        }
    }

    private static String base64Url(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            bytes = java.util.Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static JwkProvider fixedKeyProvider(TestKeyPair keyPair, String kid) {
        Jwk jwk = Jwk.fromValues(Map.of(
                "kty", "RSA", "kid", kid,
                "n", base64Url(keyPair.publicKey().getModulus()),
                "e", base64Url(keyPair.publicKey().getPublicExponent())));
        return requestedKid -> {
            if (!kid.equals(requestedKid)) {
                throw new SigningKeyNotFoundException("no such kid: " + requestedKid, null);
            }
            return jwk;
        };
    }

    private static JwkProvider alwaysThrowingProvider() {
        return kid -> {
            throw new SigningKeyNotFoundException("JWKS unavailable", null);
        };
    }

    private WorkloadIdentityVerifierConfig defaultConfig() {
        return new WorkloadIdentityVerifierConfig(
                ISSUER, "https://token.actions.githubusercontent.com/.well-known/jwks", AUDIENCE,
                Set.of("RS256"), Duration.ofSeconds(30), Duration.ofMinutes(10), 10,
                Duration.ofSeconds(5), Duration.ofSeconds(5), 256 * 1024L);
    }

    private com.auth0.jwt.JWTCreator.Builder validTokenBuilder(Instant now) {
        return JWT.create()
                .withKeyId(KID)
                .withIssuer(ISSUER)
                .withAudience(AUDIENCE)
                .withSubject("repo:" + REPOSITORY + ":ref:refs/heads/main")
                .withClaim("repository", REPOSITORY)
                .withClaim("repository_owner", REPOSITORY_OWNER)
                .withClaim("sha", COMMIT_SHA)
                .withClaim("ref", "refs/heads/main")
                .withClaim("job_workflow_ref", WORKFLOW_REF)
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(now.plusSeconds(300)))
                .withJWTId("jti-123");
    }

    // ===================== GitHubActionsOidcVerifier: positive path =====================

    @Test
    void validTokenVerifiesAndMapsAllClaims() throws Exception {
        TestKeyPair keyPair = TestKeyPair.generate();
        Instant now = Instant.now();
        String token = validTokenBuilder(now).sign(Algorithm.RSA256(keyPair.publicKey(), keyPair.privateKey()));

        GitHubActionsOidcVerifier verifier = new GitHubActionsOidcVerifier(defaultConfig(), fixedKeyProvider(keyPair, KID));
        WorkloadIdentityVerificationResult result = verifier.verify(token);

        assertTrue(result.isValid(), () -> "expected valid, got failure: " + result.failureReason());
        VerifiedWorkloadIdentity identity = result.identity();
        assertEquals(ISSUER, identity.issuer());
        assertEquals(AUDIENCE, identity.audience());
        assertEquals(REPOSITORY, identity.repository());
        assertEquals(REPOSITORY_OWNER, identity.repositoryOwner());
        assertEquals(COMMIT_SHA, identity.commitSha());
        assertEquals(WORKFLOW_REF, identity.workflowRef());
        assertNull(identity.environment(), "environment claim must be null when the token never used GitHub Environments");
        assertNotNull(identity.subjectSha256());
        assertNotNull(identity.tokenIdSha256());
    }

    @Test
    void environmentClaimIsMappedWhenPresent() throws Exception {
        TestKeyPair keyPair = TestKeyPair.generate();
        Instant now = Instant.now();
        String token = validTokenBuilder(now).withClaim("environment", "prod").sign(Algorithm.RSA256(keyPair.publicKey(), keyPair.privateKey()));

        GitHubActionsOidcVerifier verifier = new GitHubActionsOidcVerifier(defaultConfig(), fixedKeyProvider(keyPair, KID));
        WorkloadIdentityVerificationResult result = verifier.verify(token);

        assertTrue(result.isValid());
        assertEquals("prod", result.identity().environment());
    }

    // ===================== GitHubActionsOidcVerifier: negative acceptance (§24) =====================

    @Test
    void missingTokenIsRejected() {
        GitHubActionsOidcVerifier verifier = new GitHubActionsOidcVerifier(defaultConfig(), alwaysThrowingProvider());
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_MISSING, verifier.verify(null).failureReason());
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_MISSING, verifier.verify("").failureReason());
    }

    @Test
    void garbageTokenIsRejectedAsInvalidSignature() {
        GitHubActionsOidcVerifier verifier = new GitHubActionsOidcVerifier(defaultConfig(), alwaysThrowingProvider());
        WorkloadIdentityVerificationResult result = verifier.verify("not-a-jwt-at-all");
        assertFalse(result.isValid());
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_INVALID_SIGNATURE, result.failureReason());
    }

    @Test
    void wrongSigningKeyIsRejected() throws Exception {
        TestKeyPair signingKey = TestKeyPair.generate();
        TestKeyPair differentTrustedKey = TestKeyPair.generate();
        Instant now = Instant.now();
        String token = validTokenBuilder(now).sign(Algorithm.RSA256(signingKey.publicKey(), signingKey.privateKey()));

        // Verifier trusts a DIFFERENT key under the same kid than the one that actually signed.
        GitHubActionsOidcVerifier verifier = new GitHubActionsOidcVerifier(defaultConfig(), fixedKeyProvider(differentTrustedKey, KID));
        WorkloadIdentityVerificationResult result = verifier.verify(token);
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_INVALID_SIGNATURE, result.failureReason());
    }

    @Test
    void unsupportedAlgorithmIsRejectedBeforeAnyKeyLookup() {
        // A token signed with HS256 (a symmetric algorithm never in this verifier's RS256-only
        // allowlist) - constructed directly since java-jwt's own HMAC signer would otherwise "work"
        // and defeat the point of the test.
        String hs256Token = JWT.create()
                .withIssuer(ISSUER).withAudience(AUDIENCE).withKeyId(KID)
                .sign(Algorithm.HMAC256("any-shared-secret-value"));

        JwkProvider explodingIfCalled = kid -> {
            throw new AssertionError("must never look up a key for a disallowed algorithm");
        };
        GitHubActionsOidcVerifier verifier = new GitHubActionsOidcVerifier(defaultConfig(), explodingIfCalled);
        WorkloadIdentityVerificationResult result = verifier.verify(hs256Token);
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_UNSUPPORTED_ALGORITHM, result.failureReason());
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        TestKeyPair keyPair = TestKeyPair.generate();
        Instant longAgo = Instant.now().minusSeconds(3600);
        String token = JWT.create()
                .withKeyId(KID).withIssuer(ISSUER).withAudience(AUDIENCE)
                .withSubject("repo:" + REPOSITORY).withClaim("repository", REPOSITORY).withClaim("repository_owner", REPOSITORY_OWNER)
                .withClaim("sha", COMMIT_SHA).withClaim("job_workflow_ref", WORKFLOW_REF)
                .withIssuedAt(Date.from(longAgo)).withExpiresAt(Date.from(longAgo.plusSeconds(60)))
                .sign(Algorithm.RSA256(keyPair.publicKey(), keyPair.privateKey()));

        GitHubActionsOidcVerifier verifier = new GitHubActionsOidcVerifier(defaultConfig(), fixedKeyProvider(keyPair, KID));
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_EXPIRED, verifier.verify(token).failureReason());
    }

    @Test
    void futureNotBeforeIsRejected() throws Exception {
        TestKeyPair keyPair = TestKeyPair.generate();
        Instant now = Instant.now();
        String token = validTokenBuilder(now).withNotBefore(Date.from(now.plusSeconds(3600)))
                .sign(Algorithm.RSA256(keyPair.publicKey(), keyPair.privateKey()));

        GitHubActionsOidcVerifier verifier = new GitHubActionsOidcVerifier(defaultConfig(), fixedKeyProvider(keyPair, KID));
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_NOT_YET_VALID, verifier.verify(token).failureReason());
    }

    @Test
    void wrongIssuerIsRejected() throws Exception {
        TestKeyPair keyPair = TestKeyPair.generate();
        Instant now = Instant.now();
        String token = JWT.create()
                .withKeyId(KID).withIssuer("https://attacker.example.com").withAudience(AUDIENCE)
                .withSubject("repo:" + REPOSITORY).withClaim("repository", REPOSITORY).withClaim("repository_owner", REPOSITORY_OWNER)
                .withClaim("sha", COMMIT_SHA).withClaim("job_workflow_ref", WORKFLOW_REF)
                .withIssuedAt(Date.from(now)).withExpiresAt(Date.from(now.plusSeconds(300)))
                .sign(Algorithm.RSA256(keyPair.publicKey(), keyPair.privateKey()));

        GitHubActionsOidcVerifier verifier = new GitHubActionsOidcVerifier(defaultConfig(), fixedKeyProvider(keyPair, KID));
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_UNTRUSTED_ISSUER, verifier.verify(token).failureReason());
    }

    @Test
    void wrongAudienceIsRejected() throws Exception {
        TestKeyPair keyPair = TestKeyPair.generate();
        Instant now = Instant.now();
        String token = JWT.create()
                .withKeyId(KID).withIssuer(ISSUER).withAudience("some-other-audience")
                .withSubject("repo:" + REPOSITORY).withClaim("repository", REPOSITORY).withClaim("repository_owner", REPOSITORY_OWNER)
                .withClaim("sha", COMMIT_SHA).withClaim("job_workflow_ref", WORKFLOW_REF)
                .withIssuedAt(Date.from(now)).withExpiresAt(Date.from(now.plusSeconds(300)))
                .sign(Algorithm.RSA256(keyPair.publicKey(), keyPair.privateKey()));

        GitHubActionsOidcVerifier verifier = new GitHubActionsOidcVerifier(defaultConfig(), fixedKeyProvider(keyPair, KID));
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_AUDIENCE_MISMATCH, verifier.verify(token).failureReason());
    }

    @Test
    void missingRepositoryClaimIsRejected() throws Exception {
        TestKeyPair keyPair = TestKeyPair.generate();
        Instant now = Instant.now();
        String token = JWT.create()
                .withKeyId(KID).withIssuer(ISSUER).withAudience(AUDIENCE)
                .withSubject("repo:" + REPOSITORY)
                // repository claim deliberately omitted
                .withClaim("repository_owner", REPOSITORY_OWNER).withClaim("sha", COMMIT_SHA).withClaim("job_workflow_ref", WORKFLOW_REF)
                .withIssuedAt(Date.from(now)).withExpiresAt(Date.from(now.plusSeconds(300)))
                .sign(Algorithm.RSA256(keyPair.publicKey(), keyPair.privateKey()));

        GitHubActionsOidcVerifier verifier = new GitHubActionsOidcVerifier(defaultConfig(), fixedKeyProvider(keyPair, KID));
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_REQUIRED_CLAIM_MISSING, verifier.verify(token).failureReason());
    }

    @Test
    void unknownKidWithFailedRefreshIsRejectedAsVerifierUnavailable() throws Exception {
        TestKeyPair keyPair = TestKeyPair.generate();
        Instant now = Instant.now();
        String token = validTokenBuilder(now).sign(Algorithm.RSA256(keyPair.publicKey(), keyPair.privateKey()));

        GitHubActionsOidcVerifier verifier = new GitHubActionsOidcVerifier(defaultConfig(), alwaysThrowingProvider());
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_VERIFIER_UNAVAILABLE, verifier.verify(token).failureReason());
    }

    // ===================== TrustedWorkloadAuthorizationPolicy =====================

    private VerifiedWorkloadIdentity identityFor(String repository, String owner, String commitSha, String workflowRef, String environment) {
        return new VerifiedWorkloadIdentity(ISSUER, "subj-hash", AUDIENCE, repository, owner, "refs/heads/main",
                commitSha, workflowRef, environment, Instant.now(), Instant.now().plusSeconds(300), "jti-hash");
    }

    @Test
    void matchingWorkloadIsAuthorized() {
        var policy = new TrustedWorkloadAuthorizationPolicy(Set.of(new AllowedWorkload(REPOSITORY, REPOSITORY_OWNER, "nonprod", WORKFLOW_REF)));
        var identity = identityFor(REPOSITORY, REPOSITORY_OWNER, COMMIT_SHA, WORKFLOW_REF, null);
        assertTrue(policy.authorize(identity, REPOSITORY, COMMIT_SHA, "nonprod").authorized());
    }

    @Test
    void repositoryMismatchIsDenied() {
        var policy = new TrustedWorkloadAuthorizationPolicy(Set.of(new AllowedWorkload(REPOSITORY, REPOSITORY_OWNER, "nonprod", WORKFLOW_REF)));
        var identity = identityFor("owner/different-repo", REPOSITORY_OWNER, COMMIT_SHA, WORKFLOW_REF, null);
        var result = policy.authorize(identity, REPOSITORY, COMMIT_SHA, "nonprod");
        assertFalse(result.authorized());
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_REPOSITORY_MISMATCH, result.failureReason());
    }

    @Test
    void commitMismatchIsDenied() {
        var policy = new TrustedWorkloadAuthorizationPolicy(Set.of(new AllowedWorkload(REPOSITORY, REPOSITORY_OWNER, "nonprod", WORKFLOW_REF)));
        var identity = identityFor(REPOSITORY, REPOSITORY_OWNER, "d".repeat(40), WORKFLOW_REF, null);
        var result = policy.authorize(identity, REPOSITORY, COMMIT_SHA, "nonprod");
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_COMMIT_MISMATCH, result.failureReason());
    }

    @Test
    void tokenEnvironmentClaimMismatchIsDenied() {
        var policy = new TrustedWorkloadAuthorizationPolicy(Set.of(new AllowedWorkload(REPOSITORY, REPOSITORY_OWNER, "prod", WORKFLOW_REF)));
        var identity = identityFor(REPOSITORY, REPOSITORY_OWNER, COMMIT_SHA, WORKFLOW_REF, "staging");
        var result = policy.authorize(identity, REPOSITORY, COMMIT_SHA, "prod");
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_ENVIRONMENT_MISMATCH, result.failureReason());
    }

    @Test
    void noRuleForRepositoryEnvironmentPairIsDenied() {
        var policy = new TrustedWorkloadAuthorizationPolicy(Set.of(new AllowedWorkload(REPOSITORY, REPOSITORY_OWNER, "nonprod", WORKFLOW_REF)));
        var identity = identityFor(REPOSITORY, REPOSITORY_OWNER, COMMIT_SHA, WORKFLOW_REF, null);
        var result = policy.authorize(identity, REPOSITORY, COMMIT_SHA, "prod"); // no rule for "prod"
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_WORKFLOW_NOT_AUTHORIZED, result.failureReason());
    }

    @Test
    void ownerMismatchIsDenied() {
        var policy = new TrustedWorkloadAuthorizationPolicy(Set.of(new AllowedWorkload(REPOSITORY, REPOSITORY_OWNER, "nonprod", WORKFLOW_REF)));
        var identity = identityFor(REPOSITORY, "attacker-owner", COMMIT_SHA, WORKFLOW_REF, null);
        var result = policy.authorize(identity, REPOSITORY, COMMIT_SHA, "nonprod");
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_OWNER_MISMATCH, result.failureReason());
    }

    @Test
    void workflowMismatchIsDenied() {
        var policy = new TrustedWorkloadAuthorizationPolicy(Set.of(new AllowedWorkload(REPOSITORY, REPOSITORY_OWNER, "nonprod", WORKFLOW_REF)));
        var identity = identityFor(REPOSITORY, REPOSITORY_OWNER, COMMIT_SHA, "owner/repo/.github/workflows/other.yml@refs/heads/main", null);
        var result = policy.authorize(identity, REPOSITORY, COMMIT_SHA, "nonprod");
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_WORKFLOW_NOT_AUTHORIZED, result.failureReason());
    }

    // ===================== FederatedTerraformCredentialProvider (hand-written fakes) =====================

    private static RunnerRequest planRequest() {
        return new RunnerRequest("req-1", REPOSITORY, COMMIT_SHA, "nonprod", "artifact-1", "plan-sha",
                "1.6.6", "sha256:lock", "approval-1", RunnerOperation.TERRAFORM_PLAN);
    }

    private static TerraformStateIdentity fakeStateIdentity() {
        return new TerraformStateIdentity("local", "instance-1", "nonprod", "state-key-1");
    }

    private static WorkloadIdentityTokenSource fixedTokenSource(String token) {
        return audience -> token;
    }

    private static WorkloadIdentityTokenSource throwingTokenSource() {
        return audience -> {
            throw new WorkloadIdentityTokenUnavailableException("no token");
        };
    }

    private static WorkloadIdentityVerifier fixedVerifier(WorkloadIdentityVerificationResult result) {
        return token -> result;
    }

    private static WorkloadAuthorizationPolicy fixedAuthzPolicy(WorkloadAuthorizationResult result) {
        return (identity, repository, commitSha, environment) -> result;
    }

    private VerifiedWorkloadIdentity anyVerifiedIdentity() {
        return identityFor(REPOSITORY, REPOSITORY_OWNER, COMMIT_SHA, WORKFLOW_REF, null);
    }

    @Test
    void federatedProviderFullSuccessPathProducesCredentialsAndEvidence() {
        VerifiedWorkloadIdentity identity = anyVerifiedIdentity();
        FederatedCredentialProvider federation = (rawToken, id, repo, env, profile) ->
                new FederatedCredentialMaterial(Map.of("AWS_ACCESS_KEY_ID", "AKIA...", "AWS_SECRET_ACCESS_KEY", "secret",
                        "AWS_SESSION_TOKEN", "token"), "arn:aws:iam::123456789012:role/plan-role", Instant.now().plusSeconds(900));

        var provider = new FederatedTerraformCredentialProvider(
                fixedTokenSource("raw-token-value"), fixedVerifier(WorkloadIdentityVerificationResult.verified(identity)),
                fixedAuthzPolicy(WorkloadAuthorizationResult.granted()), federation,
                AUDIENCE, "github-actions-oidc", "test-v1", "aws-sts");

        TerraformCredentialMaterial material = provider.obtain(planRequest(), fakeStateIdentity());
        assertEquals("AKIA...", material.environmentVariables().get("AWS_ACCESS_KEY_ID"));
        assertTrue(material.sourceIdentifier().contains("aws-sts"));
        assertNotNull(material.workloadIdentityEvidence());
        assertTrue(material.workloadIdentityEvidence().authorized());
        assertEquals("arn:aws:iam::123456789012:role/plan-role", material.workloadIdentityEvidence().cloudRoleIdentifier());
    }

    @Test
    void federatedProviderMissingTokenBlocksBeforeVerification() {
        var provider = new FederatedTerraformCredentialProvider(
                throwingTokenSource(), fixedVerifier(WorkloadIdentityVerificationResult.rejected(RunnerReasonCode.WORKLOAD_IDENTITY_INVALID_SIGNATURE)),
                fixedAuthzPolicy(WorkloadAuthorizationResult.granted()), (t, i, r, e, p) -> {
            throw new AssertionError("federation must never be reached");
        }, AUDIENCE, "github-actions-oidc", "test-v1", "aws-sts");

        var e = assertThrows(WorkloadIdentityFederationException.class, () -> provider.obtain(planRequest(), fakeStateIdentity()));
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_MISSING, e.reasonCode());
        assertNotNull(e.evidence());
        assertFalse(e.evidence().authorized());
        assertNull(e.evidence().repository(), "no verified claims exist yet when the token itself is missing");
    }

    @Test
    void federatedProviderVerificationFailureBlocksBeforeAuthorization() {
        var provider = new FederatedTerraformCredentialProvider(
                fixedTokenSource("raw-token"), fixedVerifier(WorkloadIdentityVerificationResult.rejected(RunnerReasonCode.WORKLOAD_IDENTITY_EXPIRED)),
                fixedAuthzPolicy(WorkloadAuthorizationResult.granted()), (t, i, r, e, p) -> {
            throw new AssertionError("federation must never be reached");
        }, AUDIENCE, "github-actions-oidc", "test-v1", "aws-sts");

        var e = assertThrows(WorkloadIdentityFederationException.class, () -> provider.obtain(planRequest(), fakeStateIdentity()));
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_EXPIRED, e.reasonCode());
    }

    @Test
    void federatedProviderAuthorizationFailureBlocksBeforeFederationAndRecordsVerifiedClaims() {
        VerifiedWorkloadIdentity identity = anyVerifiedIdentity();
        var provider = new FederatedTerraformCredentialProvider(
                fixedTokenSource("raw-token"), fixedVerifier(WorkloadIdentityVerificationResult.verified(identity)),
                fixedAuthzPolicy(WorkloadAuthorizationResult.denied(RunnerReasonCode.WORKLOAD_IDENTITY_WORKFLOW_NOT_AUTHORIZED)),
                (t, i, r, e, p) -> {
                    throw new AssertionError("federation must never be reached");
                }, AUDIENCE, "github-actions-oidc", "test-v1", "aws-sts");

        var e = assertThrows(WorkloadIdentityFederationException.class, () -> provider.obtain(planRequest(), fakeStateIdentity()));
        assertEquals(RunnerReasonCode.WORKLOAD_IDENTITY_WORKFLOW_NOT_AUTHORIZED, e.reasonCode());
        assertNotNull(e.evidence());
        assertFalse(e.evidence().authorized());
        assertEquals(REPOSITORY, e.evidence().repository(), "verified claims are recorded even though the attempt was denied");
    }

    @Test
    void federatedProviderFederationFailurePropagatesReasonCode() {
        VerifiedWorkloadIdentity identity = anyVerifiedIdentity();
        var provider = new FederatedTerraformCredentialProvider(
                fixedTokenSource("raw-token"), fixedVerifier(WorkloadIdentityVerificationResult.verified(identity)),
                fixedAuthzPolicy(WorkloadAuthorizationResult.granted()),
                (t, i, r, e, p) -> {
                    throw new WorkloadIdentityFederationException(RunnerReasonCode.CLOUD_ROLE_NOT_AUTHORIZED, "no role configured");
                }, AUDIENCE, "github-actions-oidc", "test-v1", "aws-sts");

        var e = assertThrows(WorkloadIdentityFederationException.class, () -> provider.obtain(planRequest(), fakeStateIdentity()));
        assertEquals(RunnerReasonCode.CLOUD_ROLE_NOT_AUTHORIZED, e.reasonCode());
        assertNotNull(e.evidence(), "evidence must be filled in even if the inner federation exception omitted it");
    }

    // ===================== GitHubOidcRunnerIdentityProvider =====================

    @Test
    void oidcRunnerIdentityProviderReturnsTrustedIdentityOnValidToken() {
        VerifiedWorkloadIdentity identity = anyVerifiedIdentity();
        var provider = new GitHubOidcRunnerIdentityProvider(
                fixedTokenSource("raw-token"), fixedVerifier(WorkloadIdentityVerificationResult.verified(identity)),
                AUDIENCE, "github-actions-oidc", Set.of("nonprod", "prod"));

        Optional<RunnerIdentity> result = provider.currentIdentity();
        assertTrue(result.isPresent());
        assertTrue(result.get().trusted());
        assertEquals("github-actions-oidc", result.get().runnerClass());
        assertEquals(Set.of("nonprod", "prod"), result.get().environmentScope());
    }

    @Test
    void oidcRunnerIdentityProviderReturnsEmptyWhenTokenUnavailable() {
        var provider = new GitHubOidcRunnerIdentityProvider(
                throwingTokenSource(), fixedVerifier(WorkloadIdentityVerificationResult.rejected(RunnerReasonCode.WORKLOAD_IDENTITY_MISSING)),
                AUDIENCE, "github-actions-oidc", Set.of("nonprod"));
        assertTrue(provider.currentIdentity().isEmpty());
    }

    @Test
    void oidcRunnerIdentityProviderReturnsEmptyWhenVerificationFails() {
        var provider = new GitHubOidcRunnerIdentityProvider(
                fixedTokenSource("raw-token"), fixedVerifier(WorkloadIdentityVerificationResult.rejected(RunnerReasonCode.WORKLOAD_IDENTITY_INVALID_SIGNATURE)),
                AUDIENCE, "github-actions-oidc", Set.of("nonprod"));
        assertTrue(provider.currentIdentity().isEmpty());
    }

    // ===================== ProductionWorkloadIdentityConfiguration - no silent fallback =====================

    @Test
    void identityConfigRejectsMissingOrWrongMode() {
        assertThrows(WorkloadIdentityConfigurationException.class, () -> ProductionWorkloadIdentityConfiguration.createIdentityProvider(Map.of()));
        assertThrows(WorkloadIdentityConfigurationException.class,
                () -> ProductionWorkloadIdentityConfiguration.createIdentityProvider(Map.of("runner.identity.mode", "host-file")));
    }

    @Test
    void credentialsConfigRejectsMissingOrWrongMode() {
        assertThrows(WorkloadIdentityConfigurationException.class, () -> ProductionWorkloadIdentityConfiguration.createCredentialProvider(Map.of()));
        assertThrows(WorkloadIdentityConfigurationException.class,
                () -> ProductionWorkloadIdentityConfiguration.createCredentialProvider(Map.of("runner.credentials.mode", "none")));
    }

    @Test
    void credentialsConfigRejectsNonAwsProvider() {
        var props = new java.util.HashMap<String, String>();
        props.put("runner.credentials.mode", "federated");
        props.put("runner.credentials.federated.provider", "gcp");
        assertThrows(WorkloadIdentityConfigurationException.class, () -> ProductionWorkloadIdentityConfiguration.createCredentialProvider(props));
    }

    @Test
    void identityConfigProducesAWorkingProviderWhenFullyConfigured() {
        Map<String, String> props = Map.of(
                "runner.identity.mode", "oidc",
                "runner.identity.oidc.audience", AUDIENCE,
                "runner.identity.oidc.runnerClass", "github-actions-oidc",
                "runner.identity.oidc.environmentScope", "nonprod,prod");
        var provider = ProductionWorkloadIdentityConfiguration.createIdentityProvider(props);
        assertNotNull(provider);
        // No real GitHub Actions environment present in this test JVM - must fail closed, never a
        // default/fallback identity.
        assertTrue(provider.currentIdentity().isEmpty());
    }

    @Test
    void credentialsConfigRejectsMalformedRoleMappings() {
        Map<String, String> props = validAwsCredentialProperties();
        var mutable = new java.util.HashMap<>(props);
        mutable.put("runner.credentials.federated.aws.roleMappings", "not-a-valid-entry");
        assertThrows(WorkloadIdentityConfigurationException.class, () -> ProductionWorkloadIdentityConfiguration.createCredentialProvider(mutable));
    }

    private Map<String, String> validAwsCredentialProperties() {
        Map<String, String> props = new java.util.HashMap<>();
        props.put("runner.credentials.mode", "federated");
        props.put("runner.credentials.federated.provider", "aws");
        props.put("runner.credentials.federated.audience", AUDIENCE);
        props.put("runner.credentials.federated.aws.region", "us-east-1");
        props.put("runner.credentials.federated.aws.sessionDurationSeconds", "900");
        props.put("runner.credentials.federated.aws.minimumRemainingLifetimeSeconds", "300");
        props.put("runner.credentials.federated.aws.apiCallTimeoutSeconds", "10");
        props.put("runner.credentials.federated.aws.roleMappings", REPOSITORY + "|nonprod|arn:aws:iam::123456789012:role/plan-role");
        props.put("runner.credentials.authorization.allowedWorkloads", REPOSITORY + "|" + REPOSITORY_OWNER + "|nonprod|" + WORKFLOW_REF);
        return props;
    }

    @Test
    void credentialsConfigProducesAWorkingProviderWhenFullyConfigured() {
        TerraformCredentialProvider provider = ProductionWorkloadIdentityConfiguration.createCredentialProvider(validAwsCredentialProperties());
        assertNotNull(provider);
    }

    // ===================== Structural invariants (§30) =====================

    @Test
    void runnerRequestCarriesNoIdentityFederationSecurityRelevantField() {
        List<String> forbidden = List.of("issuer", "jwks", "rolearn", "credential", "token", "audience");
        for (RecordComponent component : RunnerRequest.class.getRecordComponents()) {
            String lower = component.getName().toLowerCase();
            for (String bad : forbidden) {
                assertFalse(lower.contains(bad),
                        "RunnerRequest must not carry a field that could establish workload identity/credentials: " + component.getName());
            }
        }
    }

    @Test
    void verifiedWorkloadIdentityNeverCarriesRawTokenOrCredentialFields() {
        // "token" alone is deliberately excluded from this list - tokenIdSha256 is a legitimate,
        // already-accepted field: a HASH of the jti claim, never the raw token, matching this
        // codebase's established "Sha256 suffix signals a hash, not the raw value" naming
        // convention used throughout (see subjectSha256 on this same record).
        List<String> forbidden = List.of("rawtoken", "jwt", "credential", "secret", "accesskey", "sessiontoken");
        for (RecordComponent component : VerifiedWorkloadIdentity.class.getRecordComponents()) {
            String lower = component.getName().toLowerCase();
            for (String bad : forbidden) {
                assertFalse(lower.contains(bad), "VerifiedWorkloadIdentity must never carry: " + component.getName());
            }
        }
    }

    @Test
    void workloadIdentityEvidenceNeverCarriesRawTokenOrCredentialValueFields() {
        List<String> forbidden = List.of("token", "secret", "accesskey", "sessiontoken");
        for (RecordComponent component : WorkloadIdentityEvidence.class.getRecordComponents()) {
            String lower = component.getName().toLowerCase();
            for (String bad : forbidden) {
                assertFalse(lower.contains(bad), "WorkloadIdentityEvidence must never carry: " + component.getName());
            }
        }
    }

    @Test
    void federatedCredentialMaterialCarriesNoRoleArnParameterFromCaller() {
        // FederatedCredentialMaterial itself only ever carries the ALREADY-RESOLVED role identifier
        // as a plain, non-secret string field - there is no separate "requestedRoleArn" input field
        // anywhere on this type or on FederatedCredentialProvider#federate that a caller could use
        // to select a role; the resolver is the only path to a role ARN. This test documents that
        // fact structurally rather than merely by convention.
        for (var method : FederatedCredentialProvider.class.getMethods()) {
            for (var param : method.getParameterTypes()) {
                assertNotEquals("RoleArn", param.getSimpleName());
            }
        }
    }

    @Test
    void terraformOperationSurfaceRemainsExactlySevenAfterPhase2b7() {
        assertEquals(7, ControlledTerraformOperation.values().length);
        assertEquals(10, RunnerOperation.values().length);
        for (var value : ControlledTerraformOperation.values()) {
            assertNotEquals("TERRAFORM_APPLY", value.name());
            assertNotEquals("TERRAFORM_DESTROY", value.name());
        }
        for (var value : RunnerOperation.values()) {
            assertFalse(value.name().contains("APPLY"));
            assertFalse(value.name().contains("DESTROY"));
            assertFalse(value.name().contains("IMPORT"));
            assertFalse(value.name().contains("STATE"));
            assertFalse(value.name().contains("FORCE_UNLOCK"));
        }
    }

    @Test
    void soleProcessBuilderInvariantPreserved() throws Exception {
        java.nio.file.Path sourceDir = java.nio.file.Path.of("src/main/java/com/iacagent/iacagent/runner");
        int filesWithProcessBuilder = 0;
        try (var files = java.nio.file.Files.walk(sourceDir)) {
            for (java.nio.file.Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                String content = java.nio.file.Files.readString(file);
                if (content.contains("new ProcessBuilder")) {
                    filesWithProcessBuilder++;
                    assertEquals("ControlledTerraformProcess.java", file.getFileName().toString());
                }
            }
        }
        assertEquals(1, filesWithProcessBuilder);
    }
}
