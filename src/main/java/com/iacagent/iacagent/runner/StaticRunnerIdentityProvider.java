package com.iacagent.iacagent.runner;

import java.util.Optional;

/** A fixed identity supplied once at construction - test/dev use only. {@link HostAttestedRunnerIdentityProvider}
 * is the hardened local/reference attestation source; neither is a production identity mechanism
 * (Gate C, {@code docs/phase-2b2-runner-hardening.md} §15). */
public final class StaticRunnerIdentityProvider implements RunnerIdentityProvider {

    private final RunnerIdentity identity;

    public StaticRunnerIdentityProvider(RunnerIdentity identity) {
        if (identity == null) {
            throw new IllegalArgumentException("identity is required");
        }
        this.identity = identity;
    }

    @Override
    public Optional<RunnerIdentity> currentIdentity() {
        return Optional.of(identity);
    }
}
