package com.iacagent.iacagent.identity;

import com.auth0.jwk.GuavaCachedJwkProvider;
import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.iacagent.iacagent.runner.RunnerReasonCode;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;

/**
 * Production {@link WorkloadIdentityVerifier} for GitHub Actions' real OIDC token format
 * (issuer {@code https://token.actions.githubusercontent.com}) - not a generic/invented token
 * shape. Verification order, each step deterministic and separately reason-coded rather than
 * inferred from a library exception type:
 * <ol>
 *   <li>algorithm allowlist (header {@code alg}, checked BEFORE any key lookup or signature attempt -
 *   {@code alg=none} or anything outside {@link WorkloadIdentityVerifierConfig#allowedAlgorithms()}
 *   is rejected immediately);
 *   <li>signature (via {@code com.auth0:java-jwt}, keyed by the header {@code kid} resolved through
 *   {@link #jwkProvider} - never a key the token itself supplies out-of-band);
 *   <li>issuer (pinned to {@link WorkloadIdentityVerifierConfig#trustedIssuer()});
 *   <li>audience (pinned to {@link WorkloadIdentityVerifierConfig#expectedAudience()});
 *   <li>expiration / not-before (with {@link WorkloadIdentityVerifierConfig#clockSkewTolerance()});
 *   <li>issued-at sanity (present, not implausibly in the future);
 *   <li>required claims present ({@code repository}, {@code repository_owner}, {@code sha},
 *   {@code sub}, and a workflow reference claim - GitHub emits {@code job_workflow_ref} for reusable
 *   workflows and always emits {@code workflow}; this verifier accepts either, preferring
 *   {@code job_workflow_ref} when present since it is the more precise identifier).
 * </ol>
 *
 * <p>The header is decoded via {@link JWT#decode} BEFORE signature verification ONLY to read
 * {@code alg}/{@code kid} - no payload claim is ever trusted until the full signature check below it
 * succeeds. {@code rawToken} itself is never logged, persisted, or included in any exception message
 * this class throws or returns.
 */
public final class GitHubActionsOidcVerifier implements WorkloadIdentityVerifier {

    private final WorkloadIdentityVerifierConfig config;
    private final JwkProvider jwkProvider;

    public GitHubActionsOidcVerifier(WorkloadIdentityVerifierConfig config) {
        this(config, new GuavaCachedJwkProvider(new BoundedHttpsJwkProvider(config), config.jwksCacheSize(), config.jwksCacheTtl()));
    }

    /** Test-only seam: substitutes the real HTTPS-backed {@link JwkProvider} with any other
     * implementation (e.g. one backed by a local key pair) - never used by
     * {@link #GitHubActionsOidcVerifier(WorkloadIdentityVerifierConfig)}, the sole production
     * construction path. */
    GitHubActionsOidcVerifier(WorkloadIdentityVerifierConfig config, JwkProvider jwkProvider) {
        if (config == null) {
            throw new IllegalArgumentException("config is required");
        }
        if (jwkProvider == null) {
            throw new IllegalArgumentException("jwkProvider is required");
        }
        this.config = config;
        this.jwkProvider = jwkProvider;
    }

    @Override
    public WorkloadIdentityVerificationResult verify(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return WorkloadIdentityVerificationResult.rejected(RunnerReasonCode.WORKLOAD_IDENTITY_MISSING);
        }

        DecodedJWT unverifiedHeader;
        try {
            unverifiedHeader = JWT.decode(rawToken);
        } catch (JWTDecodeException e) {
            return WorkloadIdentityVerificationResult.rejected(RunnerReasonCode.WORKLOAD_IDENTITY_INVALID_SIGNATURE);
        }

        String alg = unverifiedHeader.getAlgorithm();
        if (alg == null || !config.allowedAlgorithms().contains(alg)) {
            return WorkloadIdentityVerificationResult.rejected(RunnerReasonCode.WORKLOAD_IDENTITY_UNSUPPORTED_ALGORITHM);
        }

        String kid = unverifiedHeader.getKeyId();
        if (kid == null || kid.isBlank()) {
            return WorkloadIdentityVerificationResult.rejected(RunnerReasonCode.WORKLOAD_IDENTITY_REQUIRED_CLAIM_MISSING);
        }

        RSAPublicKey publicKey;
        try {
            Jwk jwk = jwkProvider.get(kid);
            PublicKey key = jwk.getPublicKey();
            if (!(key instanceof RSAPublicKey rsaPublicKey)) {
                return WorkloadIdentityVerificationResult.rejected(RunnerReasonCode.WORKLOAD_IDENTITY_UNSUPPORTED_ALGORITHM);
            }
            publicKey = rsaPublicKey;
        } catch (JwkException | RuntimeException e) {
            return WorkloadIdentityVerificationResult.rejected(RunnerReasonCode.WORKLOAD_IDENTITY_VERIFIER_UNAVAILABLE);
        }

        DecodedJWT verified;
        try {
            // Signature verification ONLY here - java-jwt's default verifier ALSO enforces exp/nbf
            // by default even with no claim constraints added, so those checks are explicitly
            // neutralized (huge leeway / ignored) here and re-implemented as deliberate, separately
            // reason-coded manual comparisons below, rather than relying on library exception types
            // to imply which specific claim failed. Signature verification itself always runs
            // first internally in java-jwt, before any registered-claim check - it is therefore
            // still safe to treat ANY exception surfacing here as a signature failure.
            long effectivelyUnbounded = java.time.Duration.ofDays(365L * 100).toSeconds(); // ~100 years - large enough to neutralize the check, small enough to avoid overflow in the library's own Date-millis arithmetic
            verified = JWT.require(Algorithm.RSA256(publicKey, null))
                    .acceptExpiresAt(effectivelyUnbounded)
                    .acceptNotBefore(effectivelyUnbounded)
                    .acceptIssuedAt(effectivelyUnbounded)
                    .build()
                    .verify(rawToken);
        } catch (JWTVerificationException e) {
            return WorkloadIdentityVerificationResult.rejected(RunnerReasonCode.WORKLOAD_IDENTITY_INVALID_SIGNATURE);
        }

        if (!config.trustedIssuer().equals(verified.getIssuer())) {
            return WorkloadIdentityVerificationResult.rejected(RunnerReasonCode.WORKLOAD_IDENTITY_UNTRUSTED_ISSUER);
        }

        List<String> audience = verified.getAudience();
        if (audience == null || !audience.contains(config.expectedAudience())) {
            return WorkloadIdentityVerificationResult.rejected(RunnerReasonCode.WORKLOAD_IDENTITY_AUDIENCE_MISMATCH);
        }

        Instant now = Instant.now();
        long skewSeconds = config.clockSkewTolerance().toSeconds();

        Instant expiresAt = verified.getExpiresAtAsInstant();
        if (expiresAt == null || now.isAfter(expiresAt.plusSeconds(skewSeconds))) {
            return WorkloadIdentityVerificationResult.rejected(RunnerReasonCode.WORKLOAD_IDENTITY_EXPIRED);
        }

        Instant notBefore = verified.getNotBeforeAsInstant();
        if (notBefore != null && now.isBefore(notBefore.minusSeconds(skewSeconds))) {
            return WorkloadIdentityVerificationResult.rejected(RunnerReasonCode.WORKLOAD_IDENTITY_NOT_YET_VALID);
        }

        Instant issuedAt = verified.getIssuedAtAsInstant();
        if (issuedAt == null || now.isBefore(issuedAt.minusSeconds(skewSeconds))) {
            // Present-but-implausible (issued in the future beyond tolerance) is the same class of
            // problem as "not yet valid" - collapsed into one truthful reason rather than inventing
            // a distinct one this verifier cannot actually distinguish further.
            return WorkloadIdentityVerificationResult.rejected(
                    issuedAt == null ? RunnerReasonCode.WORKLOAD_IDENTITY_REQUIRED_CLAIM_MISSING : RunnerReasonCode.WORKLOAD_IDENTITY_NOT_YET_VALID);
        }

        String subject = verified.getSubject();
        String repository = stringClaim(verified, "repository");
        String repositoryOwner = stringClaim(verified, "repository_owner");
        String sha = stringClaim(verified, "sha");
        String ref = stringClaim(verified, "ref");
        String workflowRef = stringClaim(verified, "job_workflow_ref");
        if (workflowRef == null) {
            workflowRef = stringClaim(verified, "workflow");
        }
        String environment = stringClaim(verified, "environment"); // legitimately absent unless GH Environments used
        String jti = verified.getId();

        if (subject == null || repository == null || repositoryOwner == null || sha == null || workflowRef == null) {
            return WorkloadIdentityVerificationResult.rejected(RunnerReasonCode.WORKLOAD_IDENTITY_REQUIRED_CLAIM_MISSING);
        }

        VerifiedWorkloadIdentity identity = new VerifiedWorkloadIdentity(
                verified.getIssuer(),
                sha256Hex(subject),
                config.expectedAudience(),
                repository,
                repositoryOwner,
                ref,
                sha,
                workflowRef,
                environment,
                issuedAt,
                expiresAt,
                jti == null ? null : sha256Hex(jti));
        return WorkloadIdentityVerificationResult.verified(identity);
    }

    private static String stringClaim(DecodedJWT jwt, String name) {
        Claim claim = jwt.getClaim(name);
        return claim == null || claim.isNull() || claim.isMissing() ? null : claim.asString();
    }

    private static String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available on any supported JVM", e);
        }
    }
}
