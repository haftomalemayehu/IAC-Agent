package com.iacagent.iacagent.runner;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The {@link ProcessEnvironmentPolicy} for {@code TERRAFORM_INIT}/{@code TERRAFORM_VALIDATE}/
 * {@code TERRAFORM_PROVIDERS_SCHEMA} - a sibling of {@link TerraformProcessEnvironmentPolicy}, not
 * a modification of it, exactly as that class was itself added as a sibling of
 * {@link AllowlistProcessEnvironmentPolicy} in Phase 2B-3. {@code TERRAFORM_VERSION}/
 * {@code TERRAFORM_FMT_CHECK}/{@code TERRAFORM_SHOW_PLAN_JSON} never load provider plugins and so
 * have no need for any of the entries this class adds - keeping them on the unmodified Phase 2B-3
 * policy means none of that phase's accepted, exact-environment-content tests are affected by this
 * phase at all.
 *
 * <p>Adds, beyond the Phase 2B-3 base set: {@code TF_CLI_CONFIG_FILE} and {@code TF_PLUGIN_CACHE_DIR}
 * pointing at workspace-local paths - created by trusted runner code
 * ({@link RunnerWorkspaceManager#prepareTerraformCliConfig}) before {@code init} is ever launched -
 * and {@code TF_DATA_DIR}, pinning the {@code .terraform} metadata directory explicitly inside the
 * workspace even though that is already Terraform's own default for a workspace-rooted working
 * directory. None of these three is ever a value a caller or repository could influence: all three
 * are derived only from the internally-computed {@code workspace} argument, never from
 * {@link RunnerRequest}. See {@code docs/phase-2b4-controlled-init-validation.md} §"Terraform CLI
 * config" and §"Provider plugin execution risk" for why plugin discovery must never be allowed to
 * fall back to an ambient host location such as {@code ~/.terraformrc}, the caller's {@code PATH},
 * or an arbitrary filesystem directory.
 */
public final class TerraformInitProcessEnvironmentPolicy implements ProcessEnvironmentPolicy {

    private final TerraformProcessEnvironmentPolicy base = new TerraformProcessEnvironmentPolicy();

    @Override
    public ProcessEnvironment buildFor(RunnerRequest request, Path workspace) {
        if (request == null) {
            throw new IllegalArgumentException("request is required");
        }
        if (workspace == null) {
            throw new IllegalArgumentException("workspace is required");
        }
        Map<String, String> variables = new LinkedHashMap<>(base.buildFor(request, workspace).variables());
        variables.put("TF_CLI_CONFIG_FILE", workspace.resolve("terraform.rc").toString());
        variables.put("TF_PLUGIN_CACHE_DIR", workspace.resolve("plugin-cache").toString());
        variables.put("TF_DATA_DIR", workspace.resolve(".terraform").toString());
        return new ProcessEnvironment(variables);
    }
}
