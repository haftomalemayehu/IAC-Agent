package com.iacagent.iacagent.runner;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

/**
 * The only place a {@link ControlledTerraformCommand} is constructed. Every argv element is either
 * a fixed program constant ({@code "version"}, {@code "-json"}, {@code "fmt"}, {@code "-check"},
 * {@code "-no-color"}, {@code "-recursive"}, {@code "show"}), the trusted executable's own resolved
 * real path, or an internally-derived workspace/artifact {@link Path} - never anything read from a
 * {@link RunnerRequest} field, repository content, or an environment variable. There is
 * deliberately no method here shaped like {@code build(List<String> args)}.
 */
public final class TerraformCommandFactory {

    private final ProcessEnvironmentPolicy environmentPolicy;
    private final ProcessEnvironmentPolicy initEnvironmentPolicy;

    /** Phase 2B-3 constructor, unchanged - {@code environmentPolicy} is used for every command
     * this factory builds, including (if called) the Phase 2B-4 init-family ones below. Existing
     * callers built this way therefore never see a {@code TF_CLI_CONFIG_FILE}/{@code TF_PLUGIN_CACHE_DIR}
     * entry, which is fine since none of them ever call {@link #initCommand}/{@link #validateCommand}/
     * {@link #providersSchemaCommand}. */
    public TerraformCommandFactory(ProcessEnvironmentPolicy environmentPolicy) {
        this(environmentPolicy, environmentPolicy);
    }

    /** Phase 2B-4: {@code initEnvironmentPolicy} is used ONLY for {@link #initCommand}/
     * {@link #validateCommand}/{@link #providersSchemaCommand} - a deliberately separate policy
     * from the one {@link #versionCommand}/{@link #fmtCheckCommand}/{@link #showPlanJsonCommand}
     * use, since only the init-family operations need a runner-owned Terraform CLI config/plugin
     * cache location (see {@code docs/phase-2b4-controlled-init-validation.md} §"Terraform CLI
     * config"). */
    public TerraformCommandFactory(ProcessEnvironmentPolicy environmentPolicy, ProcessEnvironmentPolicy initEnvironmentPolicy) {
        if (environmentPolicy == null) {
            throw new IllegalArgumentException("environmentPolicy is required");
        }
        if (initEnvironmentPolicy == null) {
            throw new IllegalArgumentException("initEnvironmentPolicy is required");
        }
        this.environmentPolicy = environmentPolicy;
        this.initEnvironmentPolicy = initEnvironmentPolicy;
    }

    public ControlledTerraformCommand versionCommand(RunnerRequest request, TerraformExecutableDescriptor executable, Path workingDirectory, Duration timeout) {
        List<String> argv = List.of(executable.executablePath().toString(), "version", "-json");
        return new ControlledTerraformCommand(
                ControlledTerraformOperation.TERRAFORM_VERSION, argv, workingDirectory, environmentPolicy.buildFor(request, workingDirectory), timeout);
    }

    public ControlledTerraformCommand fmtCheckCommand(RunnerRequest request, TerraformExecutableDescriptor executable, Path workingDirectory, Duration timeout) {
        List<String> argv = List.of(executable.executablePath().toString(), "fmt", "-check", "-no-color", "-recursive", workingDirectory.toString());
        return new ControlledTerraformCommand(
                ControlledTerraformOperation.TERRAFORM_FMT_CHECK, argv, workingDirectory, environmentPolicy.buildFor(request, workingDirectory), timeout);
    }

    public ControlledTerraformCommand showPlanJsonCommand(
            RunnerRequest request, TerraformExecutableDescriptor executable, Path workingDirectory, Path stagedPlanPath, Duration timeout) {
        List<String> argv = List.of(executable.executablePath().toString(), "show", "-json", stagedPlanPath.toString());
        return new ControlledTerraformCommand(
                ControlledTerraformOperation.TERRAFORM_SHOW_PLAN_JSON, argv, workingDirectory, environmentPolicy.buildFor(request, workingDirectory), timeout);
    }

    /** {@code terraform init -backend=false -input=false -no-color -lockfile=readonly} - argv is
     * entirely fixed program constants plus the trusted executable's own resolved path; there is no
     * parameter here through which a backend-config argument, {@code -upgrade}, {@code -reconfigure},
     * {@code -migrate-state}, or {@code -force-copy} could ever be introduced. */
    public ControlledTerraformCommand initCommand(RunnerRequest request, TerraformExecutableDescriptor executable, Path workingDirectory, Duration timeout) {
        List<String> argv = List.of(executable.executablePath().toString(), "init", "-backend=false", "-input=false", "-no-color", "-lockfile=readonly");
        return new ControlledTerraformCommand(
                ControlledTerraformOperation.TERRAFORM_INIT, argv, workingDirectory, initEnvironmentPolicy.buildFor(request, workingDirectory), timeout);
    }

    /** {@code terraform validate -json -no-color}. Only ever launched by the coordinator after a
     * successful {@link #initCommand} against the same staged configuration in the same call. */
    public ControlledTerraformCommand validateCommand(RunnerRequest request, TerraformExecutableDescriptor executable, Path workingDirectory, Duration timeout) {
        List<String> argv = List.of(executable.executablePath().toString(), "validate", "-json", "-no-color");
        return new ControlledTerraformCommand(
                ControlledTerraformOperation.TERRAFORM_VALIDATE, argv, workingDirectory, initEnvironmentPolicy.buildFor(request, workingDirectory), timeout);
    }

    /** {@code terraform providers schema -json}. Only ever launched by the coordinator after a
     * successful {@link #initCommand} against the same staged configuration in the same call. */
    public ControlledTerraformCommand providersSchemaCommand(RunnerRequest request, TerraformExecutableDescriptor executable, Path workingDirectory, Duration timeout) {
        List<String> argv = List.of(executable.executablePath().toString(), "providers", "schema", "-json");
        return new ControlledTerraformCommand(
                ControlledTerraformOperation.TERRAFORM_PROVIDERS_SCHEMA, argv, workingDirectory, initEnvironmentPolicy.buildFor(request, workingDirectory), timeout);
    }
}
