package com.iacagent.iacagent.identity.aws;

import com.iacagent.iacagent.identity.TerraformCredentialProfile;
import com.iacagent.iacagent.identity.VerifiedWorkloadIdentity;

/**
 * Resolves which AWS IAM role (if any) an already verified-and-authorized workload identity may
 * assume for a given repository/environment/credential profile. The repository/request MUST NEVER
 * be able to choose an arbitrary role ARN - every implementation resolves the role from trusted,
 * control-plane-owned configuration only, keyed by facts already established by verification and
 * authorization (never by a caller-supplied role name/ARN/account id).
 */
public interface TrustedCloudRoleResolver {
    CloudRoleResolution resolve(String repository, String environment, VerifiedWorkloadIdentity identity, TerraformCredentialProfile profile);
}
