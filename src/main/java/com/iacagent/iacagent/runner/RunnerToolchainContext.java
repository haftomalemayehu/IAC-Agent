package com.iacagent.iacagent.runner;

/**
 * The runner-side, trusted observation of what Terraform toolchain this runner instance actually
 * has - never derived from a {@link RunnerRequest} field. {@link ControlledRunner} compares the
 * request's claimed {@code terraformVersion}/{@code providerLockHash} against these observed
 * values; a mismatch fails closed.
 *
 * <p>Phase 2B-1 scope note: this models a single, runner-global toolchain observation (one
 * installed Terraform version, one currently-trusted provider-lock hash) rather than resolving a
 * provider-lock hash per artifact by actually inspecting a {@code .terraform.lock.hcl} bundled
 * with the plan - that per-artifact resolution, and actually invoking {@code terraform version},
 * are deferred to a later 2B slice (see the Phase 2B-1 design doc). No Terraform process is
 * invoked by this phase.
 */
public interface RunnerToolchainContext {
    String observedTerraformVersion();

    String observedProviderLockHash();
}
