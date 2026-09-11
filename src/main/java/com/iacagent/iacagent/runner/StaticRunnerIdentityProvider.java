package com.iacagent.iacagent.runner;

/** Phase 2B-1's deterministic identity source: a fixed identity supplied once at construction. */
public final class StaticRunnerIdentityProvider implements RunnerIdentityProvider {

    private final RunnerIdentity identity;

    public StaticRunnerIdentityProvider(RunnerIdentity identity) {
        if (identity == null) {
            throw new IllegalArgumentException("identity is required");
        }
        this.identity = identity;
    }

    @Override
    public RunnerIdentity currentIdentity() {
        return identity;
    }
}
