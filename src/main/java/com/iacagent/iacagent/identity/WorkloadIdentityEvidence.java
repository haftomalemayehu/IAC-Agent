package com.iacagent.iacagent.identity;

import java.time.Instant;

/**
 * The sanitized, durable audit record of one verify → authorize → federate attempt - embedded into
 * {@code TerraformPlanEvidence} exactly like every other Terraform-adjacent evidence type in this
 * codebase. Contains ONLY non-secret facts: never the raw token, never any credential value (access
 * key, secret key, session token). {@code subjectSha256}/{@code tokenIdSha256} are hashes, not the
 * underlying claim values, matching {@link VerifiedWorkloadIdentity}'s own discipline.
 *
 * <p>Populated for BOTH outcomes - a successful federation AND a denied one - so an operator can see
 * WHY a plan was blocked (which claim mismatched, which policy rule was missing) without ever seeing
 * anything sensitive. Fields that were never reached (e.g. {@code cloudRoleIdentifier} when
 * authorization itself failed before federation was even attempted) are {@code null}, not a
 * placeholder.
 */
public record WorkloadIdentityEvidence(
        String issuer,
        String subjectSha256,
        String audience,
        String repository,
        String repositoryOwner,
        String workflowRef,
        String ref,
        String environment,
        String commitSha,
        Instant issuedAt,
        Instant expiresAt,
        Instant verifiedAt,
        String verifierType,
        String verifierVersion,
        boolean authorized,
        String credentialProviderType,
        String cloudRoleIdentifier,
        Instant credentialExpiresAt
) {
    public WorkloadIdentityEvidence {
        if (verifiedAt == null) {
            throw new IllegalArgumentException("verifiedAt is required");
        }
        if (verifierType == null || verifierType.isBlank()) {
            throw new IllegalArgumentException("verifierType is required");
        }
    }

    /** Builds the evidence for a fully successful verify+authorize+federate attempt. */
    public static WorkloadIdentityEvidence success(
            VerifiedWorkloadIdentity identity, Instant verifiedAt, String verifierType, String verifierVersion,
            String credentialProviderType, String cloudRoleIdentifier, Instant credentialExpiresAt) {
        return new WorkloadIdentityEvidence(
                identity.issuer(), identity.subjectSha256(), identity.audience(), identity.repository(),
                identity.repositoryOwner(), identity.workflowRef(), identity.ref(), identity.environment(), identity.commitSha(),
                identity.issuedAt(), identity.expiresAt(), verifiedAt, verifierType, verifierVersion,
                true, credentialProviderType, cloudRoleIdentifier, credentialExpiresAt);
    }

    /** Builds the evidence for a denial that occurred AFTER identity verification succeeded (e.g.
     * an authorization or federation failure) - the identity's own verified claims are still worth
     * recording for audit even though the attempt was ultimately denied. */
    public static WorkloadIdentityEvidence deniedAfterVerification(
            VerifiedWorkloadIdentity identity, Instant verifiedAt, String verifierType, String verifierVersion) {
        return new WorkloadIdentityEvidence(
                identity.issuer(), identity.subjectSha256(), identity.audience(), identity.repository(),
                identity.repositoryOwner(), identity.workflowRef(), identity.ref(), identity.environment(), identity.commitSha(),
                identity.issuedAt(), identity.expiresAt(), verifiedAt, verifierType, verifierVersion,
                false, null, null, null);
    }

    /** Builds the evidence for a denial that occurred BEFORE identity verification ever succeeded
     * (e.g. no token at all, or an invalid signature) - there are no verified claims to record. */
    public static WorkloadIdentityEvidence deniedBeforeVerification(Instant verifiedAt, String verifierType, String verifierVersion) {
        return new WorkloadIdentityEvidence(
                null, null, null, null, null, null, null, null, null,
                null, null, verifiedAt, verifierType, verifierVersion,
                false, null, null, null);
    }
}
