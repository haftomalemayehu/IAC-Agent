package com.iacagent.iacagent.identity;

import com.iacagent.iacagent.identity.aws.AwsStsFederatedCredentialProvider;
import com.iacagent.iacagent.identity.aws.StaticTrustedCloudRoleResolver;
import com.iacagent.iacagent.identity.aws.TrustedCloudRoleResolver;
import com.iacagent.iacagent.runner.FederatedTerraformCredentialProvider;
import com.iacagent.iacagent.runner.GitHubOidcRunnerIdentityProvider;
import com.iacagent.iacagent.runner.RunnerIdentityProvider;
import com.iacagent.iacagent.runner.TerraformCredentialProvider;

import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * The two sole production wiring entry points for Gate C: {@link #createIdentityProvider} and
 * {@link #createCredentialProvider}. Both REQUIRE their respective {@code mode} property to be
 * exactly the one supported value - any other value (including absent) throws
 * {@link WorkloadIdentityConfigurationException} rather than defaulting to anything. Neither method
 * has a branch that could return {@code HostAttestedRunnerIdentityProvider}/
 * {@code NoOpTerraformCredentialProvider}/a static-credential provider - exactly the same
 * "structurally impossible, not merely undocumented" discipline
 * {@code com.iacagent.iacagent.runner.jdbc.RunnerLedgerConfiguration} established for Gate B.
 *
 * <p>Reference/test identity and credential implementations remain fully constructible directly by
 * test code (see {@code StaticRunnerIdentityProvider}, {@code HostAttestedRunnerIdentityProvider},
 * {@code NoOpTerraformCredentialProvider}) - just never reachable through this factory.
 */
public final class ProductionWorkloadIdentityConfiguration {

    private static final String VERIFIER_TYPE = "github-actions-oidc";
    private static final String VERIFIER_VERSION = "2b7-v1";
    private static final String AWS_CREDENTIAL_PROVIDER_TYPE = "aws-sts";

    private ProductionWorkloadIdentityConfiguration() {
    }

    /** {@code runner.identity.mode} must be exactly {@code "oidc"}. Required keys under
     * {@code runner.identity.oidc.}: {@code audience}, {@code runnerClass},
     * {@code environmentScope} (comma-separated). */
    public static RunnerIdentityProvider createIdentityProvider(Map<String, String> properties) {
        requireExact(properties, "runner.identity.mode", "oidc");
        String audience = requireProperty(properties, "runner.identity.oidc.audience");
        String runnerClass = requireProperty(properties, "runner.identity.oidc.runnerClass");
        Set<String> environmentScope = parseCsv(requireProperty(properties, "runner.identity.oidc.environmentScope"));

        WorkloadIdentityVerifier verifier = new GitHubActionsOidcVerifier(WorkloadIdentityVerifierConfig.githubActionsDefaults(audience));
        WorkloadIdentityTokenSource tokenSource = new GitHubActionsIdTokenSource();
        return new GitHubOidcRunnerIdentityProvider(tokenSource, verifier, audience, runnerClass, environmentScope);
    }

    /** {@code runner.credentials.mode} must be exactly {@code "federated"}, and
     * {@code runner.credentials.federated.provider} must be exactly {@code "aws"} (the only
     * federation target this phase ships). Required keys under {@code runner.credentials.federated.}:
     * {@code audience}, {@code aws.region}, {@code aws.sessionDurationSeconds},
     * {@code aws.minimumRemainingLifetimeSeconds}, {@code aws.apiCallTimeoutSeconds},
     * {@code aws.roleMappings} ({@code "repository|environment|roleArn;..."}); and under
     * {@code runner.credentials.authorization.}: {@code allowedWorkloads}
     * ({@code "repository|repositoryOwner|environment|workflowRef;..."}). */
    public static TerraformCredentialProvider createCredentialProvider(Map<String, String> properties) {
        requireExact(properties, "runner.credentials.mode", "federated");
        requireExact(properties, "runner.credentials.federated.provider", "aws");

        String audience = requireProperty(properties, "runner.credentials.federated.audience");
        String region = requireProperty(properties, "runner.credentials.federated.aws.region");
        Duration sessionDuration = Duration.ofSeconds(requireLong(properties, "runner.credentials.federated.aws.sessionDurationSeconds"));
        Duration minimumRemainingLifetime = Duration.ofSeconds(requireLong(properties, "runner.credentials.federated.aws.minimumRemainingLifetimeSeconds"));
        Duration apiCallTimeout = Duration.ofSeconds(requireLong(properties, "runner.credentials.federated.aws.apiCallTimeoutSeconds"));
        Map<StaticTrustedCloudRoleResolver.RoleMappingKey, String> roleMappings =
                parseRoleMappings(requireProperty(properties, "runner.credentials.federated.aws.roleMappings"));
        Set<AllowedWorkload> allowedWorkloads = parseAllowedWorkloads(requireProperty(properties, "runner.credentials.authorization.allowedWorkloads"));

        TrustedCloudRoleResolver roleResolver = new StaticTrustedCloudRoleResolver(roleMappings);
        FederatedCredentialProvider federatedCredentialProvider =
                new AwsStsFederatedCredentialProvider(roleResolver, region, sessionDuration, minimumRemainingLifetime, apiCallTimeout);
        WorkloadAuthorizationPolicy authorizationPolicy = new TrustedWorkloadAuthorizationPolicy(allowedWorkloads);
        WorkloadIdentityVerifier verifier = new GitHubActionsOidcVerifier(WorkloadIdentityVerifierConfig.githubActionsDefaults(audience));
        WorkloadIdentityTokenSource tokenSource = new GitHubActionsIdTokenSource();

        return new FederatedTerraformCredentialProvider(
                tokenSource, verifier, authorizationPolicy, federatedCredentialProvider,
                audience, VERIFIER_TYPE, VERIFIER_VERSION, AWS_CREDENTIAL_PROVIDER_TYPE);
    }

    private static Map<StaticTrustedCloudRoleResolver.RoleMappingKey, String> parseRoleMappings(String raw) {
        Map<StaticTrustedCloudRoleResolver.RoleMappingKey, String> result = new java.util.LinkedHashMap<>();
        for (String record : raw.split(";")) {
            if (record.isBlank()) {
                continue;
            }
            String[] fields = record.split("\\|");
            if (fields.length != 3) {
                throw new WorkloadIdentityConfigurationException("malformed role mapping entry (expected repository|environment|roleArn): " + record);
            }
            result.put(new StaticTrustedCloudRoleResolver.RoleMappingKey(fields[0], fields[1], TerraformCredentialProfile.PLAN), fields[2]);
        }
        if (result.isEmpty()) {
            throw new WorkloadIdentityConfigurationException("runner.credentials.federated.aws.roleMappings must declare at least one mapping");
        }
        return result;
    }

    private static Set<AllowedWorkload> parseAllowedWorkloads(String raw) {
        Set<AllowedWorkload> result = new LinkedHashSet<>();
        for (String record : raw.split(";")) {
            if (record.isBlank()) {
                continue;
            }
            String[] fields = record.split("\\|");
            if (fields.length != 4) {
                throw new WorkloadIdentityConfigurationException(
                        "malformed allowed-workload entry (expected repository|repositoryOwner|environment|workflowRef): " + record);
            }
            result.add(new AllowedWorkload(fields[0], fields[1], fields[2], fields[3]));
        }
        if (result.isEmpty()) {
            throw new WorkloadIdentityConfigurationException("runner.credentials.authorization.allowedWorkloads must declare at least one entry");
        }
        return result;
    }

    private static Set<String> parseCsv(String raw) {
        Set<String> result = new LinkedHashSet<>();
        for (String value : raw.split(",")) {
            if (!value.isBlank()) {
                result.add(value.trim());
            }
        }
        return result;
    }

    private static void requireExact(Map<String, String> properties, String key, String expectedValue) {
        String value = properties == null ? null : properties.get(key);
        if (!expectedValue.equals(value)) {
            throw new WorkloadIdentityConfigurationException(key + " must be exactly '" + expectedValue + "', got: " + value);
        }
    }

    private static String requireProperty(Map<String, String> properties, String key) {
        String value = properties.get(key);
        if (value == null || value.isBlank()) {
            throw new WorkloadIdentityConfigurationException("required configuration property is missing: " + key);
        }
        return value;
    }

    private static long requireLong(Map<String, String> properties, String key) {
        String raw = requireProperty(properties, key);
        try {
            return Long.parseLong(raw.trim());
        } catch (NumberFormatException e) {
            throw new WorkloadIdentityConfigurationException("configuration property " + key + " must be an integer, got: " + raw);
        }
    }
}
