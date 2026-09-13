package com.iacagent.iacagent.runner;

/**
 * The ONLY source of credential material a {@code TERRAFORM_PLAN} process may receive - never a
 * static secret embedded in a {@link RunnerRequest}, repository content, or this package's own
 * source. Gate C (real workload identity/OIDC) governs what a PRODUCTION implementation of this
 * interface must do; Phase 2B-5 ships only {@link NoOpTerraformCredentialProvider} (honest for the
 * {@link ReferenceLocalBackendResolver} local backend, which needs no cloud credentials at all) -
 * see {@code docs/phase-2b5-controlled-plan-state-read.md} §8.
 */
public interface TerraformCredentialProvider {
    TerraformCredentialMaterial obtain(RunnerRequest request, TerraformStateIdentity stateIdentity);
}
