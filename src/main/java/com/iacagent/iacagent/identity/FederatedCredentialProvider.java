package com.iacagent.iacagent.identity;

/**
 * Obtains short-lived, purpose-scoped cloud credentials for an ALREADY verified-and-authorized
 * workload identity. This is the last of three deliberately separate steps
 * (verify → authorize → federate, see the package javadoc-equivalent design doc §1) - an
 * implementation must never itself re-derive trust from anything other than the
 * {@link VerifiedWorkloadIdentity} and {@code rawToken} it is handed; it never resolves a role/
 * credential target from anything caller/request-supplied (see
 * {@code com.iacagent.iacagent.identity.aws.TrustedCloudRoleResolver}).
 *
 * <p>{@code rawToken} is required here (not just the parsed {@link VerifiedWorkloadIdentity})
 * because real federation protocols (e.g. AWS STS {@code AssumeRoleWithWebIdentity}) require
 * presenting the original signed token to the cloud provider for ITS OWN independent verification
 * against its configured trust policy - implementations must never log, persist, or otherwise
 * retain it beyond the federation call itself.
 */
public interface FederatedCredentialProvider {
    FederatedCredentialMaterial federate(
            String rawToken, VerifiedWorkloadIdentity identity, String repository, String environment, TerraformCredentialProfile profile);
}
