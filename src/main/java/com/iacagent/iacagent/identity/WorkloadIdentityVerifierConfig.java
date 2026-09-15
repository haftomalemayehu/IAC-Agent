package com.iacagent.iacagent.identity;

import java.time.Duration;
import java.util.Set;

/**
 * Trusted, control-plane-owned configuration for a {@link WorkloadIdentityVerifier} - every field
 * here is application configuration, NEVER derived from a token's own claims, a
 * {@link com.iacagent.iacagent.runner.RunnerRequest} field, or repository content. In particular,
 * {@code jwksUri} is fixed at construction and never re-derived per verification call - a token can
 * never influence where its own verification keys are fetched from (closes the SSRF surface a
 * "trust the token's own {@code jku}/issuer-metadata-URL" design would otherwise open).
 */
public record WorkloadIdentityVerifierConfig(
        String trustedIssuer,
        String jwksUri,
        String expectedAudience,
        Set<String> allowedAlgorithms,
        Duration clockSkewTolerance,
        Duration jwksCacheTtl,
        int jwksCacheSize,
        Duration jwksConnectTimeout,
        Duration jwksReadTimeout,
        long jwksMaxResponseBytes
) {
    public WorkloadIdentityVerifierConfig {
        require(trustedIssuer, "trustedIssuer");
        require(jwksUri, "jwksUri");
        require(expectedAudience, "expectedAudience");
        if (!jwksUri.startsWith("https://")) {
            throw new IllegalArgumentException("jwksUri must be HTTPS: " + jwksUri);
        }
        if (allowedAlgorithms == null || allowedAlgorithms.isEmpty()) {
            throw new IllegalArgumentException("allowedAlgorithms must be non-empty - never default to an implicit allowlist");
        }
        allowedAlgorithms = Set.copyOf(allowedAlgorithms);
        if (allowedAlgorithms.contains("none")) {
            throw new IllegalArgumentException("'none' must never be an allowed algorithm");
        }
        if (clockSkewTolerance == null || clockSkewTolerance.isNegative() || clockSkewTolerance.compareTo(Duration.ofMinutes(5)) > 0) {
            throw new IllegalArgumentException("clockSkewTolerance must be between 0 and 5 minutes");
        }
        if (jwksCacheTtl == null || jwksCacheTtl.isNegative() || jwksCacheTtl.isZero()) {
            throw new IllegalArgumentException("jwksCacheTtl must be positive");
        }
        if (jwksCacheSize < 1) {
            throw new IllegalArgumentException("jwksCacheSize must be >= 1");
        }
        if (jwksConnectTimeout == null || jwksConnectTimeout.isNegative() || jwksConnectTimeout.isZero()) {
            throw new IllegalArgumentException("jwksConnectTimeout must be positive");
        }
        if (jwksReadTimeout == null || jwksReadTimeout.isNegative() || jwksReadTimeout.isZero()) {
            throw new IllegalArgumentException("jwksReadTimeout must be positive");
        }
        if (jwksMaxResponseBytes < 1024) {
            throw new IllegalArgumentException("jwksMaxResponseBytes must be at least 1024");
        }
    }

    /** GitHub Actions' real, well-documented OIDC issuer/JWKS endpoints - the trusted production
     * default for {@link GitHubActionsOidcVerifier}. {@code expectedAudience} still must be supplied
     * explicitly by the caller - it is deployment-specific (e.g. an AWS account/role identifier used
     * as the audience convention), never something this library should default. */
    public static WorkloadIdentityVerifierConfig githubActionsDefaults(String expectedAudience) {
        return new WorkloadIdentityVerifierConfig(
                "https://token.actions.githubusercontent.com",
                "https://token.actions.githubusercontent.com/.well-known/jwks",
                expectedAudience,
                Set.of("RS256"),
                Duration.ofSeconds(30),
                Duration.ofMinutes(10),
                10,
                Duration.ofSeconds(5),
                Duration.ofSeconds(5),
                256 * 1024L);
    }

    private static void require(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
    }
}
