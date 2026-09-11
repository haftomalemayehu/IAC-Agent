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

    public TerraformCommandFactory(ProcessEnvironmentPolicy environmentPolicy) {
        if (environmentPolicy == null) {
            throw new IllegalArgumentException("environmentPolicy is required");
        }
        this.environmentPolicy = environmentPolicy;
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
}
