package com.iacagent.iacagent.runner;

/**
 * The host/runtime boundary that supplies a runner's own identity. This is the ONLY source
 * {@link ControlledRunner} consults for identity - never a {@link RunnerRequest} field, because
 * no such field exists on that type. A caller cannot self-assert identity because there is no
 * parameter, header, or request field through which one could even attempt to.
 *
 * <p>Phase 2B-1 uses {@link StaticRunnerIdentityProvider}: a fixed identity configured once, at
 * construction time, by whoever deploys/wires this runner instance - analogous to how an actual
 * runner host would be provisioned with a fixed identity (a machine role, a service account) that
 * a request arriving at it cannot change. Real dynamic attestation (OIDC workload identity) is
 * explicitly deferred to a later 2B slice - see the Phase 2B-1 design doc's "deferred 2B-2 items."
 */
public interface RunnerIdentityProvider {
    RunnerIdentity currentIdentity();
}
