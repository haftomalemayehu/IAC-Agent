package com.iacagent.iacagent.identity;

/**
 * Thrown when production workload-identity/credential-federation configuration is missing,
 * malformed, or requests an unsupported mode - always thrown BEFORE any verifier/token-source/
 * federation client is constructed, so a misconfigured deployment fails at startup rather than
 * silently falling back to local identity or no-op credentials. Never contains a secret value.
 */
public final class WorkloadIdentityConfigurationException extends RuntimeException {
    public WorkloadIdentityConfigurationException(String message) {
        super(message);
    }
}
