package com.iacagent.iacagent.identity.aws;

import com.iacagent.iacagent.identity.TerraformCredentialProfile;
import com.iacagent.iacagent.identity.VerifiedWorkloadIdentity;

import java.util.Map;

/**
 * The reference {@link TrustedCloudRoleResolver}: a fixed map from
 * {@code (repository, environment, profile)} to a single trusted role ARN, supplied entirely at
 * construction by whoever operates this control plane. Deliberately does not consult the
 * {@link VerifiedWorkloadIdentity} at all for the LOOKUP KEY (only {@code repository}/
 * {@code environment}/{@code profile}, all already independently verified/authorized by the time
 * this is called) - the identity parameter exists on the interface for a future resolver that might
 * need finer-grained per-workflow role selection, not because this reference implementation uses it.
 */
public final class StaticTrustedCloudRoleResolver implements TrustedCloudRoleResolver {

    private record Key(String repository, String environment, TerraformCredentialProfile profile) {
    }

    private final Map<Key, String> roleArnsByKey;

    public StaticTrustedCloudRoleResolver(Map<RoleMappingKey, String> roleArnsByRepositoryEnvironmentProfile) {
        if (roleArnsByRepositoryEnvironmentProfile == null) {
            throw new IllegalArgumentException("roleArnsByRepositoryEnvironmentProfile is required");
        }
        java.util.Map<Key, String> copy = new java.util.LinkedHashMap<>();
        for (var entry : roleArnsByRepositoryEnvironmentProfile.entrySet()) {
            RoleMappingKey k = entry.getKey();
            String roleArn = entry.getValue();
            if (roleArn == null || roleArn.isBlank()) {
                throw new IllegalArgumentException("role ARN for " + k + " must not be blank");
            }
            copy.put(new Key(k.repository(), k.environment(), k.profile()), roleArn);
        }
        this.roleArnsByKey = Map.copyOf(copy);
    }

    @Override
    public CloudRoleResolution resolve(String repository, String environment, VerifiedWorkloadIdentity identity, TerraformCredentialProfile profile) {
        if (repository == null || environment == null || identity == null || profile == null) {
            throw new IllegalArgumentException("repository, environment, identity, and profile are all required");
        }
        String roleArn = roleArnsByKey.get(new Key(repository, environment, profile));
        return roleArn == null ? CloudRoleResolution.notAuthorized() : CloudRoleResolution.resolved(roleArn);
    }

    /** The public, constructable lookup key - kept distinct from the private record above only so
     * callers building the configuration map do not need package access to construct one. */
    public record RoleMappingKey(String repository, String environment, TerraformCredentialProfile profile) {
        public RoleMappingKey {
            if (repository == null || repository.isBlank()) {
                throw new IllegalArgumentException("repository is required");
            }
            if (environment == null || environment.isBlank()) {
                throw new IllegalArgumentException("environment is required");
            }
            if (profile == null) {
                throw new IllegalArgumentException("profile is required");
            }
        }
    }
}
