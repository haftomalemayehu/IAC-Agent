package com.iacagent.iacagent.runner;

/**
 * The ONLY source of Terraform backend/state-target truth for {@code TERRAFORM_PLAN} - resolves
 * {@code (repository, environment)} to a trusted {@link TerraformBackendResolution}. There is no
 * {@link RunnerRequest} field, and no repository-content path, through which a caller could
 * influence which backend/state a plan reads: the repository may describe backend INTENT (which
 * this package's source-policy check rejects outright, per
 * {@code docs/phase-2b5-controlled-plan-state-read.md} §5 - a {@code backend} block anywhere in
 * staged configuration blocks {@code init} before it launches), but never backend AUTHORITY.
 */
public interface TrustedBackendResolver {
    TerraformBackendResolution resolve(String repository, String environment);
}
