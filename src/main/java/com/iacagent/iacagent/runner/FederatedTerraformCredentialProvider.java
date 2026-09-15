package com.iacagent.iacagent.runner;

import com.iacagent.iacagent.identity.FederatedCredentialMaterial;
import com.iacagent.iacagent.identity.FederatedCredentialProvider;
import com.iacagent.iacagent.identity.TerraformCredentialProfile;
import com.iacagent.iacagent.identity.VerifiedWorkloadIdentity;
import com.iacagent.iacagent.identity.WorkloadAuthorizationPolicy;
import com.iacagent.iacagent.identity.WorkloadAuthorizationResult;
import com.iacagent.iacagent.identity.WorkloadIdentityEvidence;
import com.iacagent.iacagent.identity.WorkloadIdentityFederationException;
import com.iacagent.iacagent.identity.WorkloadIdentityTokenSource;
import com.iacagent.iacagent.identity.WorkloadIdentityTokenUnavailableException;
import com.iacagent.iacagent.identity.WorkloadIdentityVerificationResult;
import com.iacagent.iacagent.identity.WorkloadIdentityVerifier;

import java.time.Instant;

/**
 * Phase 2B-7 production {@link TerraformCredentialProvider}: composes the three deliberately
 * separate steps this phase introduces - verify ({@link WorkloadIdentityVerifier}), authorize
 * ({@link WorkloadAuthorizationPolicy}), federate ({@link FederatedCredentialProvider}) - into the
 * existing 2B-5 credential-provider boundary {@link ControlledTerraformOperationCoordinator}
 * already calls. Every failure mode across all three steps throws {@link WorkloadIdentityFederationException}
 * carrying the precise reason code and a sanitized {@link WorkloadIdentityEvidence} snapshot - never
 * a generic exception, never a silently-degraded result.
 *
 * <p><b>Residual secret-lifetime limitation, disclosed rather than pretended away (per the Phase
 * 2B-7 authorization's own instruction):</b> {@code rawToken} and the federated credential values
 * inside {@link FederatedCredentialMaterial#environmentVariables()} are ordinary Java
 * {@link String}s. The JVM provides no supported mechanism to force-clear a {@code String}'s
 * backing storage, and neither {@code com.auth0:java-jwt} nor the AWS SDK expose a mutable-buffer
 * alternative for tokens/credentials - so this class cannot and does not claim guaranteed secure
 * erasure of these values from heap memory. What it DOES guarantee: {@code rawToken} and every
 * credential value are local to this call stack only (never stored in any field, never returned to
 * any caller beyond {@link TerraformCredentialMaterial#environmentVariables()}, which
 * {@link ControlledTerraformOperationCoordinator} itself only ever hands to the launched process's
 * environment - never logged, never placed in any evidence record).
 */
public final class FederatedTerraformCredentialProvider implements TerraformCredentialProvider {

    private final WorkloadIdentityTokenSource tokenSource;
    private final WorkloadIdentityVerifier verifier;
    private final WorkloadAuthorizationPolicy authorizationPolicy;
    private final FederatedCredentialProvider federatedCredentialProvider;
    private final String audience;
    private final String verifierType;
    private final String verifierVersion;
    private final String credentialProviderType;

    public FederatedTerraformCredentialProvider(
            WorkloadIdentityTokenSource tokenSource,
            WorkloadIdentityVerifier verifier,
            WorkloadAuthorizationPolicy authorizationPolicy,
            FederatedCredentialProvider federatedCredentialProvider,
            String audience,
            String verifierType,
            String verifierVersion,
            String credentialProviderType) {
        this.tokenSource = require(tokenSource, "tokenSource");
        this.verifier = require(verifier, "verifier");
        this.authorizationPolicy = require(authorizationPolicy, "authorizationPolicy");
        this.federatedCredentialProvider = require(federatedCredentialProvider, "federatedCredentialProvider");
        this.audience = requireString(audience, "audience");
        this.verifierType = requireString(verifierType, "verifierType");
        this.verifierVersion = requireString(verifierVersion, "verifierVersion");
        this.credentialProviderType = requireString(credentialProviderType, "credentialProviderType");
    }

    @Override
    public TerraformCredentialMaterial obtain(RunnerRequest request, TerraformStateIdentity stateIdentity) {
        if (request == null) {
            throw new IllegalArgumentException("request is required");
        }
        if (stateIdentity == null) {
            throw new IllegalArgumentException("stateIdentity is required");
        }

        String rawToken;
        try {
            rawToken = tokenSource.currentToken(audience);
        } catch (WorkloadIdentityTokenUnavailableException e) {
            throw new WorkloadIdentityFederationException(
                    RunnerReasonCode.WORKLOAD_IDENTITY_MISSING, "no workload identity token was available",
                    WorkloadIdentityEvidence.deniedBeforeVerification(Instant.now(), verifierType, verifierVersion));
        }

        WorkloadIdentityVerificationResult verification = verifier.verify(rawToken);
        if (!verification.isValid()) {
            throw new WorkloadIdentityFederationException(
                    verification.failureReason(), "workload identity verification failed",
                    WorkloadIdentityEvidence.deniedBeforeVerification(Instant.now(), verifierType, verifierVersion));
        }
        VerifiedWorkloadIdentity identity = verification.identity();
        Instant verifiedAt = Instant.now();

        WorkloadAuthorizationResult authorization = authorizationPolicy.authorize(identity, request.repository(), request.commitSha(), request.environment());
        if (!authorization.authorized()) {
            throw new WorkloadIdentityFederationException(
                    authorization.failureReason(), "workload identity authorization denied",
                    WorkloadIdentityEvidence.deniedAfterVerification(identity, verifiedAt, verifierType, verifierVersion));
        }

        FederatedCredentialMaterial cloudMaterial;
        try {
            cloudMaterial = federatedCredentialProvider.federate(rawToken, identity, request.repository(), request.environment(), TerraformCredentialProfile.PLAN);
        } catch (WorkloadIdentityFederationException e) {
            if (e.evidence() != null) {
                throw e;
            }
            throw new WorkloadIdentityFederationException(
                    e.reasonCode(), e.getMessage(),
                    WorkloadIdentityEvidence.deniedAfterVerification(identity, verifiedAt, verifierType, verifierVersion));
        }

        WorkloadIdentityEvidence evidence = WorkloadIdentityEvidence.success(
                identity, verifiedAt, verifierType, verifierVersion, credentialProviderType, cloudMaterial.cloudRoleIdentifier(), cloudMaterial.expiresAt());
        String sourceIdentifier = "oidc:" + credentialProviderType + ":" + cloudMaterial.cloudRoleIdentifier();
        return new TerraformCredentialMaterial(cloudMaterial.environmentVariables(), sourceIdentifier, evidence);
    }

    private static <T> T require(T value, String name) {
        if (value == null) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }

    private static String requireString(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }
}
