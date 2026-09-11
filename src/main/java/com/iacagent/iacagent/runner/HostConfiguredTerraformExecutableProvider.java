package com.iacagent.iacagent.runner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * The reference {@link TerraformExecutableProvider}: a Terraform binary at a location fixed by
 * trusted bootstrap code, path-safety-checked with the exact same {@code trustedRoot}/
 * {@code untrustedRoots}/real-path-per-call/ancestor-symlink discipline established for
 * {@link HostAttestedRunnerIdentityProvider} in Phase 2B-2 (kept as an independent implementation,
 * not a shared refactor of that already-accepted class, so the Phase 2B-2 trust boundary is left
 * completely untouched by this phase).
 *
 * <p>Path-safety alone does not prove this is the exact trusted Terraform binary - it only proves
 * "safe to read and execute something at this location." Content identity (SHA-256) is verified
 * separately by the caller against {@link TerraformExecutableDescriptor#expectedSha256()}, exactly
 * as {@link RunnerArtifactStore}-resolved bytes are never trusted by identity/location alone
 * elsewhere in this package.
 */
public final class HostConfiguredTerraformExecutableProvider implements TerraformExecutableProvider {

    private final Path executablePath;
    private final String expectedSha256;
    private final String expectedVersion;
    private final Path trustedToolRootReal;
    private final List<Path> untrustedRootsReal;

    /**
     * @param executablePath  the Terraform binary's path, fixed by trusted bootstrap code - never a
     *                        value derived from a {@link RunnerRequest}, repository content, or
     *                        {@code PATH}. Must textually resolve under {@code trustedToolRoot}.
     * @param expectedSha256  the SHA-256 the resolved file's content must match before execution.
     * @param expectedVersion the Terraform version this binary is expected to report.
     * @param trustedToolRoot the directory trusted bootstrap code vouches for; resolved to its real
     *                        path once, at construction.
     * @param untrustedRoots  roots the executable must never actually, physically resolve under -
     *                        expected to include at least the runner's workspace root and any
     *                        repository-checkout root. May be empty, never null.
     */
    public HostConfiguredTerraformExecutableProvider(
            Path executablePath, String expectedSha256, String expectedVersion, Path trustedToolRoot, List<Path> untrustedRoots) {
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
        if (untrustedRoots == null) {
            throw new IllegalArgumentException("untrustedRoots is required (may be empty, never null)");
        }
        this.trustedToolRootReal = resolveRequiredExisting(trustedToolRoot, "trustedToolRoot");
        this.untrustedRootsReal = untrustedRoots.stream().map(HostConfiguredTerraformExecutableProvider::resolveBestEffort).toList();
        for (Path untrusted : untrustedRootsReal) {
            if (trustedToolRootReal.startsWith(untrusted)) {
                throw new IllegalArgumentException(
                        "trustedToolRoot must not resolve underneath an untrusted root - trustedToolRoot="
                                + trustedToolRootReal + ", untrustedRoot=" + untrusted);
            }
        }
        Path resolvedExecutableParent = resolveBestEffort(requireParent(executablePath));
        if (!resolvedExecutableParent.startsWith(trustedToolRootReal)) {
            throw new IllegalArgumentException(
                    "executablePath must reside under trustedToolRoot: " + executablePath + " is not under " + trustedToolRoot);
        }
        this.executablePath = executablePath;
        this.expectedSha256 = expectedSha256;
        this.expectedVersion = expectedVersion;
    }

    private static Path requireParent(Path path) {
        Path parent = path.toAbsolutePath().normalize().getParent();
        if (parent == null) {
            throw new IllegalArgumentException("executablePath must have a parent directory");
        }
        return parent;
    }

    private static Path resolveRequiredExisting(Path root, String name) {
        try {
            return root.toRealPath();
        } catch (IOException e) {
            throw new IllegalArgumentException(name + " must resolve to a real, existing directory: " + root, e);
        }
    }

    /**
     * Resolves {@code path} to a real path where possible; if it does not exist yet, walks up to
     * the nearest EXISTING ancestor, resolves that ancestor's real path, and re-appends the missing
     * suffix textually. See {@code HostAttestedRunnerIdentityProvider#resolveBestEffort} for why a
     * plain {@code toAbsolutePath().normalize()} fallback is unsafe on platforms where part of an
     * existing ancestor is itself an OS-level symlink (e.g. macOS's {@code /var} -&gt;
     * {@code /private/var}).
     */
    private static Path resolveBestEffort(Path path) {
        if (path == null) {
            throw new IllegalArgumentException("an untrusted root must not be null");
        }
        Path absolute = path.toAbsolutePath().normalize();
        try {
            return absolute.toRealPath();
        } catch (IOException e) {
            // fall through to the nearest-existing-ancestor walk below
        }
        Path suffix = null;
        Path ancestor = absolute;
        while (ancestor != null && !Files.exists(ancestor)) {
            Path name = ancestor.getFileName();
            suffix = suffix == null ? name : name.resolve(suffix);
            ancestor = ancestor.getParent();
        }
        if (ancestor == null) {
            return absolute;
        }
        try {
            Path realAncestor = ancestor.toRealPath();
            return suffix == null ? realAncestor : realAncestor.resolve(suffix);
        } catch (IOException e) {
            return absolute;
        }
    }

    @Override
    public TerraformExecutableResolution resolve() {
        if (Files.isSymbolicLink(executablePath)) {
            return TerraformExecutableResolution.failed(TerraformExecutableResolutionOutcome.UNTRUSTED_PATH);
        }
        Path real;
        try {
            real = executablePath.toRealPath();
        } catch (IOException e) {
            return TerraformExecutableResolution.failed(TerraformExecutableResolutionOutcome.NOT_FOUND);
        }
        if (!real.startsWith(trustedToolRootReal)) {
            return TerraformExecutableResolution.failed(TerraformExecutableResolutionOutcome.UNTRUSTED_PATH);
        }
        for (Path untrusted : untrustedRootsReal) {
            if (real.startsWith(untrusted)) {
                return TerraformExecutableResolution.failed(TerraformExecutableResolutionOutcome.UNTRUSTED_PATH);
            }
        }
        if (!Files.isRegularFile(real) || !Files.isExecutable(real)) {
            return TerraformExecutableResolution.failed(TerraformExecutableResolutionOutcome.NOT_EXECUTABLE);
        }
        return TerraformExecutableResolution.resolved(new TerraformExecutableDescriptor(real, expectedSha256, expectedVersion, trustedToolRootReal));
    }
}
