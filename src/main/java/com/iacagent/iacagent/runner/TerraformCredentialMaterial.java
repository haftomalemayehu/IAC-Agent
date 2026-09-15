package com.iacagent.iacagent.runner;

import com.iacagent.iacagent.identity.WorkloadIdentityEvidence;

import java.util.Map;

/**
 * What {@link TerraformCredentialProvider#obtain} returns: environment variables to add to the
 * PLAN process's environment (on top of, never replacing, the base clear-then-allowlist policy),
 * plus a {@code sourceIdentifier} - a non-secret label (e.g. {@code "none:local-backend-reference"},
 * or (Phase 2B-7) {@code "oidc:aws-sts:<role-arn>"}) recorded in evidence so an operator can tell
 * WHERE credentials came from without the material itself ever appearing anywhere.
 *
 * <p>{@code environmentVariables} must never be logged, persisted, or otherwise leave the process
 * boundary that consumes it - {@link ControlledTerraformOperationCoordinator} adds these directly
 * to the launched process's environment and never places them in any evidence record.
 *
 * <p>{@code workloadIdentityEvidence} (Phase 2B-7) is the sanitized, non-secret audit record of the
 * verify → authorize → federate attempt that produced (or, if null, never produced - see
 * {@link NoOpTerraformCredentialProvider}) this material. Nullable for every pre-2B-7 provider and
 * for any provider that legitimately performs no workload-identity verification at all.
 */
public record TerraformCredentialMaterial(Map<String, String> environmentVariables, String sourceIdentifier, WorkloadIdentityEvidence workloadIdentityEvidence) {
    public TerraformCredentialMaterial {
        environmentVariables = environmentVariables == null ? Map.of() : Map.copyOf(environmentVariables);
        if (sourceIdentifier == null || sourceIdentifier.isBlank()) {
            throw new IllegalArgumentException("sourceIdentifier is required");
        }
    }

    /** Convenience constructor for every pre-2B-7 caller - {@code workloadIdentityEvidence} is
     * always {@code null}. */
    public TerraformCredentialMaterial(Map<String, String> environmentVariables, String sourceIdentifier) {
        this(environmentVariables, sourceIdentifier, null);
    }
}
