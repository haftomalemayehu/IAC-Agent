package com.iacagent.iacagent.runner;

import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The only place a {@link ControlledTerraformCommand} is constructed. Every argv element is either
 * a fixed program constant ({@code "version"}, {@code "-json"}, {@code "fmt"}, {@code "-check"},
 * {@code "-no-color"}, {@code "-recursive"}, {@code "show"}), the trusted executable's own resolved
 * real path, or an internally-derived workspace/artifact {@link Path} - never anything read from a
 * {@link RunnerRequest} field, repository content, or an environment variable. There is
 * deliberately no method here shaped like {@code build(List<String> args)}.
 */
public final class TerraformCommandFactory {

    /** Fixed, internally-controlled lock-acquisition timeout for the two commands that read a real
     * backend/state ({@link #initForPlanCommand}/{@link #planCommand}) - never derived from
     * {@link RunnerRequest} or any other caller/repository input. A fixed value is what makes
     * {@code TERRAFORM_STATE_LOCK_TIMEOUT} classification deterministic (Phase 2B-5 security
     * amendment): Terraform's own {@code -lock-timeout} default is 0s (fail immediately on
     * contention), which would make "timeout" and "lock already held" indistinguishable in
     * practice; a small nonzero bound gives a genuine timeout window to observe while staying short
     * enough not to materially extend a blocked request's latency. */
    private static final String LOCK_TIMEOUT_ARG = "-lock-timeout=10s";

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

    /** {@code terraform init -input=false -no-color -lockfile=readonly} - deliberately WITHOUT
     * {@code -backend=false}, used ONLY by {@code TERRAFORM_PLAN}'s internal init step against a
     * real, trusted-resolved backend. Never used for the standalone {@code TERRAFORM_INIT}/
     * {@code TERRAFORM_VALIDATE}/{@code TERRAFORM_PROVIDERS_SCHEMA} operations, which always force
     * {@code -backend=false} via {@link #initCommand}. Backend configuration itself is never passed
     * as a CLI flag here - it comes entirely from the runner-owned backend declaration file the
     * coordinator writes into the workspace before this command runs (see
     * {@link RunnerWorkspaceManager#writeTrustedLocalBackendFile}), never from a caller-supplied
     * {@code -backend-config} value. {@code extraEnvironmentVariables} carries only
     * {@link TerraformCredentialMaterial}-sourced entries, layered on top of (never replacing) the
     * base clear-then-allowlist environment. */
    public ControlledTerraformCommand initForPlanCommand(
            RunnerRequest request, TerraformExecutableDescriptor executable, Path workingDirectory, Duration timeout,
            Map<String, String> extraEnvironmentVariables) {
        List<String> argv = List.of(
                executable.executablePath().toString(), "init", "-input=false", "-no-color", "-lockfile=readonly", LOCK_TIMEOUT_ARG);
        ProcessEnvironment environment = mergeEnvironment(initEnvironmentPolicy.buildFor(request, workingDirectory), extraEnvironmentVariables);
        return new ControlledTerraformCommand(ControlledTerraformOperation.TERRAFORM_PLAN, argv, workingDirectory, environment, timeout);
    }

    /** {@code terraform plan -out=<runner-owned-path> -input=false -no-color -detailed-exitcode
     * -lock-timeout=<fixed>} - argv is entirely fixed program constants, the trusted executable's own
     * resolved path, and an internally-derived {@link Path}; there is no parameter here through
     * which {@code -destroy}, {@code -refresh-only}, {@code -target}, {@code -replace},
     * {@code -state}, {@code -state-out}, an arbitrary {@code -var}/{@code -var-file}, an arbitrary
     * {@code -parallelism}, {@code -lock=false}, or a caller-influenced lock-timeout value could
     * ever be introduced. Normal Terraform refresh/lock semantics apply - neither is disabled - see
     * {@code docs/phase-2b5-controlled-plan-state-read.md} §§19-20/20a. */
    public ControlledTerraformCommand planCommand(
            RunnerRequest request, TerraformExecutableDescriptor executable, Path workingDirectory, Path planOutputPath, Duration timeout,
            Map<String, String> extraEnvironmentVariables) {
        List<String> argv = List.of(
                executable.executablePath().toString(), "plan",
                "-out=" + planOutputPath, "-input=false", "-no-color", "-detailed-exitcode", LOCK_TIMEOUT_ARG);
        ProcessEnvironment environment = mergeEnvironment(initEnvironmentPolicy.buildFor(request, workingDirectory), extraEnvironmentVariables);
        return new ControlledTerraformCommand(ControlledTerraformOperation.TERRAFORM_PLAN, argv, workingDirectory, environment, timeout);
    }

    private static ProcessEnvironment mergeEnvironment(ProcessEnvironment base, Map<String, String> extra) {
        if (extra == null || extra.isEmpty()) {
            return base;
        }
        Map<String, String> merged = new LinkedHashMap<>(base.variables());
        merged.putAll(extra);
        return new ProcessEnvironment(merged);
    }
}
