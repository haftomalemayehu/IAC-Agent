package com.iacagent.iacagent.identity;

import java.time.Instant;
import java.util.Map;

/**
 * Short-lived cloud credential material obtained via {@link FederatedCredentialProvider}. Deliberately
 * mirrors {@code com.iacagent.iacagent.runner.TerraformCredentialMaterial}'s shape (environment
 * variables + a non-secret source identifier) but lives in this package because it additionally
 * carries the {@code expiresAt} bound the credential-lifetime checks require - a cloud-agnostic
 * concept the Terraform-process-facing type does not need to know about directly.
 *
 * <p>{@code environmentVariables}' VALUES are the actual secret material (e.g.
 * {@code AWS_SECRET_ACCESS_KEY}) - never logged, persisted, or placed in any evidence record.
 * {@code cloudRoleIdentifier} is non-secret (e.g. a role ARN) and safe to embed in audit evidence.
 */
public record FederatedCredentialMaterial(
        Map<String, String> environmentVariables,
        String cloudRoleIdentifier,
        Instant expiresAt
) {
    public FederatedCredentialMaterial {
        environmentVariables = environmentVariables == null ? Map.of() : Map.copyOf(environmentVariables);
        if (cloudRoleIdentifier == null || cloudRoleIdentifier.isBlank()) {
            throw new IllegalArgumentException("cloudRoleIdentifier is required");
        }
        if (expiresAt == null) {
            throw new IllegalArgumentException("expiresAt is required");
        }
    }
}
