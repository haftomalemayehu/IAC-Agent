package com.iacagent.iacagent.runner;

import java.util.Map;

/**
 * The exact, closed set of environment variables a future controlled process would receive. No
 * process is launched in Phase 2B-2 - this type exists to make the future contract explicit and
 * independently testable before any process-invocation code exists to consume it.
 */
public record ProcessEnvironment(Map<String, String> variables) {
    public ProcessEnvironment {
        variables = variables == null ? Map.of() : Map.copyOf(variables);
    }
}
