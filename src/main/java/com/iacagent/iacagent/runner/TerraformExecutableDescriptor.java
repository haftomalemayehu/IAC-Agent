package com.iacagent.iacagent.runner;

import java.nio.file.Path;

/**
 * A trusted, resolved Terraform executable - never a free-form string from a {@link RunnerRequest}.
 * {@code executablePath} is always the fully-resolved REAL path (no remaining symlinks anywhere in
 * it), produced only by {@link TerraformExecutableProvider#resolve()} after path-safety checks have
 * already passed; nothing else in this package constructs one directly.
 */
public record TerraformExecutableDescriptor(
        Path executablePath,
        String expectedSha256,
        String expectedVersion,
        Path trustedToolRoot
) {
    public TerraformExecutableDescriptor {
        if (executablePath == null) {
            throw new IllegalArgumentException("executablePath is required");
        }
        if (expectedSha256 == null || expectedSha256.isBlank()) {
            throw new IllegalArgumentException("expectedSha256 is required");
        }
        if (expectedVersion == null || expectedVersion.isBlank()) {
            throw new IllegalArgumentException("expectedVersion is required");
        }
        if (trustedToolRoot == null) {
            throw new IllegalArgumentException("trustedToolRoot is required");
        }
    }
}
