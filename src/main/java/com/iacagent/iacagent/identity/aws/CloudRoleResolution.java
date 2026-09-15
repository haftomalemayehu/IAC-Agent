package com.iacagent.iacagent.identity.aws;

/** The outcome of {@link TrustedCloudRoleResolver#resolve} - either a resolved, trusted role ARN, or
 * a denial (no rule matched). Never carries a caller-supplied role ARN - only a value the resolver
 * itself looked up from trusted configuration. */
public record CloudRoleResolution(String roleArn, boolean authorized) {
    public CloudRoleResolution {
        if (authorized && (roleArn == null || roleArn.isBlank())) {
            throw new IllegalArgumentException("authorized=true requires a non-blank roleArn");
        }
        if (!authorized && roleArn != null) {
            throw new IllegalArgumentException("authorized=false must not carry a roleArn");
        }
    }

    public static CloudRoleResolution resolved(String roleArn) {
        return new CloudRoleResolution(roleArn, true);
    }

    public static CloudRoleResolution notAuthorized() {
        return new CloudRoleResolution(null, false);
    }
}
