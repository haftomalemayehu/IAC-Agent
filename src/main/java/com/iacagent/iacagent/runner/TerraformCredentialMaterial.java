package com.iacagent.iacagent.runner;

import java.util.Map;

/**
 * What {@link TerraformCredentialProvider#obtain} returns: environment variables to add to the
 * PLAN process's environment (on top of, never replacing, the base clear-then-allowlist policy),
 * plus a {@code sourceIdentifier} - a non-secret label (e.g. {@code "none:local-backend-reference"},
 * or eventually {@code "oidc:aws-role:<role-arn>"}) recorded in evidence so an operator can tell
 * WHERE credentials came from without the material itself ever appearing anywhere.
 *
 * <p>{@code environmentVariables} must never be logged, persisted, or otherwise leave the process
 * boundary that consumes it - {@link ControlledTerraformOperationCoordinator} adds these directly
 * to the launched process's environment and never places them in any evidence record.
 */
public record TerraformCredentialMaterial(Map<String, String> environmentVariables, String sourceIdentifier) {
    public TerraformCredentialMaterial {
        environmentVariables = environmentVariables == null ? Map.of() : Map.copyOf(environmentVariables);
        if (sourceIdentifier == null || sourceIdentifier.isBlank()) {
            throw new IllegalArgumentException("sourceIdentifier is required");
        }
    }
}
