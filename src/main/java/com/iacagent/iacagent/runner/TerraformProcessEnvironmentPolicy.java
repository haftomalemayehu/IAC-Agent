package com.iacagent.iacagent.runner;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The {@link ProcessEnvironmentPolicy} actually wired into the Phase 2B-3 Terraform process
 * boundary - a sibling of {@link AllowlistProcessEnvironmentPolicy}, not a modification of it (that
 * class remains the generic Phase 2B-2 reference implementation, untouched and still accepted).
 * Builds a map starting from nothing, same discipline as {@link AllowlistProcessEnvironmentPolicy}:
 * never reads {@code System.getenv()} anywhere in its implementation.
 *
 * <p>Adds one entry beyond the Phase 2B-2 set: {@code CHECKPOINT_DISABLE=1}, which suppresses
 * Terraform's own upgrade/checkpoint network call - the allowed Phase 2B-3 operations need no
 * network access at all (see {@code docs/phase-2b3-controlled-terraform-process.md} §"Network
 * Assumptions"), so this removes an otherwise-unnecessary outbound call rather than relying on
 * network isolation elsewhere to block it.
 */
public final class TerraformProcessEnvironmentPolicy implements ProcessEnvironmentPolicy {

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
        variables.put("CHECKPOINT_DISABLE", "1");
        variables.put("HOME", workspace.resolve("home").toString());
        variables.put("TMPDIR", workspace.resolve("tmp").toString());
        return new ProcessEnvironment(variables);
    }
}
