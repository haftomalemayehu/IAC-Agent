package com.iacagent.iacagent.runner;

import java.util.Optional;

/**
 * The host/runtime boundary that supplies a runner's own identity. This is the ONLY source
 * {@link ControlledRunner} consults for identity - never a {@link RunnerRequest} field, because
 * no such field exists on that type. A caller cannot self-assert identity because there is no
 * parameter, header, or request field through which one could even attempt to.
 *
 * <p>Returns {@link Optional#empty()}, never a default/fallback identity, when identity cannot be
 * resolved (missing attestation source, unreadable, malformed) - added in Phase 2B-2 specifically
 * so identity-resolution failure is a first-class, distinguishable outcome
 * ({@code RUNNER_IDENTITY_UNAVAILABLE}) rather than silently degrading to some implicit
 * anonymous/local identity.
 *
 * <p>Phase 2B-1 shipped {@link StaticRunnerIdentityProvider} (test/dev only as of Phase 2B-2).
 * {@link HostAttestedRunnerIdentityProvider} is Phase 2B-2's hardened LOCAL/REFERENCE attestation
 * source: identity is read from a location fixed at construction time by whoever deploys/wires the
 * runner, never influenced by anything in a request, with symlink/regular-file/workspace-exclusion
 * checks on top. It is explicitly NOT a production identity mechanism - real dynamic attestation
 * (cloud OIDC workload identity) remains Gate C, deferred to a later 2B slice, before any of this is
 * relied on for mutation authority.
 */
public interface RunnerIdentityProvider {
    Optional<RunnerIdentity> currentIdentity();
}
