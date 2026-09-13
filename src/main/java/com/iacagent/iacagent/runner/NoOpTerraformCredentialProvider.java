package com.iacagent.iacagent.runner;

/**
 * The Phase 2B-5 reference {@link TerraformCredentialProvider}: supplies NO additional environment
 * variables at all, honestly reflecting that {@link ReferenceLocalBackendResolver}'s {@code local}
 * backend requires no cloud credentials to read/write state or acquire locks. {@code sourceIdentifier}
 * says exactly this, so evidence never has to guess why no credential material was ever supplied.
 * Gate C remains open until a real workload-identity-backed implementation exists.
 */
public final class NoOpTerraformCredentialProvider implements TerraformCredentialProvider {

    private static final String SOURCE_IDENTIFIER = "none:local-backend-reference";

    @Override
    public TerraformCredentialMaterial obtain(RunnerRequest request, TerraformStateIdentity stateIdentity) {
        if (request == null) {
            throw new IllegalArgumentException("request is required");
        }
        if (stateIdentity == null) {
            throw new IllegalArgumentException("stateIdentity is required");
        }
        return new TerraformCredentialMaterial(java.util.Map.of(), SOURCE_IDENTIFIER);
    }
}
