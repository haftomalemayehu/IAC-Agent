package com.iacagent.iacagent.runner;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

/**
 * A fully-constructed, immutable command ready for {@link ControlledTerraformProcess#execute}.
 * Every element of {@code argv} originates from a fixed program constant, the trusted executable's
 * own resolved real path, or an internally-derived workspace/artifact path - never from
 * {@link RunnerRequest}, repository content, PR text, LLM output, or an environment variable. There
 * is no constructor or factory method anywhere in this package that accepts a caller-supplied
 * {@code List<String>} of arguments and passes it through unexamined - see
 * {@link TerraformCommandFactory}, the only place instances of this type are created.
 */
public record ControlledTerraformCommand(
        ControlledTerraformOperation operation,
        List<String> argv,
        Path workingDirectory,
        ProcessEnvironment environment,
        Duration timeout
) {
    public ControlledTerraformCommand {
        if (operation == null) {
            throw new IllegalArgumentException("operation is required");
        }
        if (argv == null || argv.isEmpty()) {
            throw new IllegalArgumentException("argv must be non-empty");
        }
        argv = List.copyOf(argv);
        if (workingDirectory == null) {
            throw new IllegalArgumentException("workingDirectory is required");
        }
        if (environment == null) {
            throw new IllegalArgumentException("environment is required");
        }
        if (timeout == null || timeout.isNegative() || timeout.isZero()) {
            throw new IllegalArgumentException("timeout must be a positive duration");
        }
    }
}
