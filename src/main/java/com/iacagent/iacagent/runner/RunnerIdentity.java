package com.iacagent.iacagent.runner;

import java.util.Set;

/**
 * The identity of the runner instance itself - never the identity of a request or its caller.
 * Produced exclusively by {@link RunnerIdentityProvider}, which {@link ControlledRunner} consults
 * independently of anything in a {@link RunnerRequest}.
 */
public record RunnerIdentity(
        String runnerId,
        String runnerClass,
        Set<String> environmentScope,
        boolean trusted
) {
    public RunnerIdentity {
        if (runnerId == null || runnerId.isBlank()) {
            throw new IllegalArgumentException("runnerId is required");
        }
        if (runnerClass == null || runnerClass.isBlank()) {
            throw new IllegalArgumentException("runnerClass is required");
        }
        environmentScope = environmentScope == null ? Set.of() : Set.copyOf(environmentScope);
    }
}
