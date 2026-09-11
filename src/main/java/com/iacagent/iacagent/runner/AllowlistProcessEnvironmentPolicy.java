package com.iacagent.iacagent.runner;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The reference {@link ProcessEnvironmentPolicy}: builds a small, fixed set of entries into a map
 * that starts empty, and never reads {@code System.getenv()} anywhere in its implementation - this
 * is verified by {@code Phase2b2Tests} via a source scan, not just by inspecting the output map.
 *
 * <p>Deliberately omits {@code PATH} entirely - no process is launched yet, and when one
 * eventually is, the executable/PATH ownership invariant (roadmap SS16) requires that value to be
 * runner-controlled and explicit, never inherited, so it should be added deliberately by whatever
 * component first needs it rather than defaulted here "just in case."
 */
public final class AllowlistProcessEnvironmentPolicy implements ProcessEnvironmentPolicy {

    @Override
    public ProcessEnvironment buildFor(RunnerRequest request, Path workspace) {
        if (request == null) {
            throw new IllegalArgumentException("request is required");
        }
        if (workspace == null) {
            throw new IllegalArgumentException("workspace is required");
        }
        Map<String, String> variables = new LinkedHashMap<>();
        variables.put("TF_IN_AUTOMATION", "true");
        variables.put("TF_INPUT", "0");
        variables.put("HOME", workspace.resolve("home").toString());
        variables.put("TMPDIR", workspace.resolve("tmp").toString());
        return new ProcessEnvironment(variables);
    }
}
