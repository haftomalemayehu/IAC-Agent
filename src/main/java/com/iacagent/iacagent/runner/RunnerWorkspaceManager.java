package com.iacagent.iacagent.runner;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

/**
 * Gives each runner request its own ephemeral, single-use working directory, and stages a
 * verified artifact into it by content identity - the same identity+atomic-write+read-only
 * pattern used for TOCTOU protection in docs/phase-2a-execution-contract.md SS13, reused here
 * rather than reinvented, since it is the same underlying problem (don't let bytes staged for one
 * purpose be swapped or confused with bytes staged for another).
 *
 * <p><b>{@code runnerRequestId} is treated as untrusted, opaque metadata - never as a filesystem
 * path component.</b> The actual directory name is derived by hashing the id (SHA-256 hex, a
 * fixed-length, fixed-alphabet string that cannot contain {@code /}, {@code ..}, a leading
 * {@code /}, or any other path-traversal or separator character), so a hostile
 * {@code runnerRequestId} such as {@code "../../etc"}, {@code "/etc/passwd"}, {@code ".."}, or one
 * containing embedded separators has no way to influence where the workspace is actually placed.
 * The original id is preserved only in {@link RunnerEvidence#runnerRequestId()} for audit/lookup,
 * never interpolated into a path. The same discipline applies to artifact identifiers passed into
 * {@link #stageArtifact}: the staged filename is derived from the artifact's own recomputed
 * SHA-256, never from a caller-supplied artifact id string.
 *
 * <p>Symlink resistance: after creating a workspace directory (or staging a file into one), this
 * class resolves the REAL path ({@link Path#toRealPath}, which follows symlinks) and verifies it
 * still falls under the root's real path - a plain {@code normalize()}/{@code startsWith()} check,
 * as used at the point a path is first computed, does not by itself detect a symlink planted
 * somewhere in the resolved path components that would cause the OS to actually resolve outside
 * the root at open/write time.
 *
 * <p>Isolation guarantees this class provides: a fresh directory per {@code runnerRequestId}
 * (never reused, never shared with another request), an atomic write-then-rename into a
 * content-addressed filename (no partially-written file is ever visible at that path), best-effort
 * read-only permissions on the staged file once written, and explicit cleanup (see
 * {@link #cleanup}) that only ever touches the one workspace it is asked to remove. What it
 * deliberately does NOT do in Phase 2B-2: invoke any process inside the workspace, set or inherit
 * any environment variable, or resolve any executable/PATH - see {@link ProcessEnvironmentPolicy}
 * for the explicit, not-yet-connected future environment contract, and the Phase 2B-2 design doc
 * for what remains deferred.
 */
public final class RunnerWorkspaceManager {

    private final Path rootDirectory;

    public RunnerWorkspaceManager(Path rootDirectory) {
        if (rootDirectory == null) {
            throw new IllegalArgumentException("rootDirectory is required");
        }
        this.rootDirectory = rootDirectory.toAbsolutePath().normalize();
    }

    /** Creates (if absent) a fresh, request-scoped directory. Never shared across requests. */
    public Path createWorkspace(String runnerRequestId) {
        if (runnerRequestId == null || runnerRequestId.isBlank()) {
            throw new IllegalArgumentException("runnerRequestId is required");
        }
        try {
            Path workspace = rootDirectory.resolve(safeDirectoryName(runnerRequestId)).normalize();
            requireUnderRoot(workspace, rootDirectory);
            Files.createDirectories(workspace);
            requireUnderRoot(workspace.toRealPath(), rootDirectory.toRealPath());
            return workspace;
        } catch (IOException e) {
            throw new RunnerWorkspaceException("failed to create workspace for the given request", e);
        }
    }

    /**
     * Stages {@code content} into {@code workspace} under a content-addressed filename (derived
     * from {@code sha256Hex}, never from any caller-supplied artifact id), using
     * write-to-temp-then-atomic-rename so the final path never shows a partially-written file,
     * then marks it read-only to the extent the host filesystem's permission model supports.
     */
    public Path stageArtifact(Path workspace, String sha256Hex, byte[] content) {
        try {
            Path target = workspace.resolve("sha256-" + sha256Hex + ".tfplan");
            requireUnderRoot(target.normalize(), rootDirectory);
            Path temp = Files.createTempFile(workspace, "staging-", ".tmp");
            Files.write(temp, content);
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            requireUnderRoot(target.toRealPath(), rootDirectory.toRealPath());
            makeReadOnlyBestEffort(target);
            return target;
        } catch (IOException e) {
            throw new RunnerWorkspaceException("failed to stage artifact into workspace " + workspace, e);
        }
    }

    /**
     * Phase 2B-3: stages Terraform configuration content (for {@code TERRAFORM_FMT_CHECK}) under a
     * content-addressed {@code .tf} filename - a sibling of {@link #stageArtifact}, not a
     * modification of it, since that method's {@code .tfplan} suffix is specific to plan artifacts
     * and {@code terraform fmt} needs to find ordinary {@code .tf} files in the directory it scans.
     * Same write-to-temp-then-atomic-rename-then-read-only discipline.
     */
    public Path stageTerraformConfigFile(Path workspace, String sha256Hex, byte[] content) {
        try {
            Path target = workspace.resolve("sha256-" + sha256Hex + ".tf");
            requireUnderRoot(target.normalize(), rootDirectory);
            Path temp = Files.createTempFile(workspace, "staging-", ".tmp");
            Files.write(temp, content);
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            requireUnderRoot(target.toRealPath(), rootDirectory.toRealPath());
            makeReadOnlyBestEffort(target);
            return target;
        } catch (IOException e) {
            throw new RunnerWorkspaceException("failed to stage Terraform configuration file into workspace " + workspace, e);
        }
    }

    /**
     * Phase 2B-3 amendment: safely stages every {@code .tf} file found under an UNTRUSTED
     * repository-checkout source tree into {@code workspace}, for {@code TERRAFORM_FMT_CHECK}
     * against a full checkout rather than a single pre-resolved artifact blob. Repository content is
     * never trusted merely because it lives under a checkout root the caller vouches for - only
     * {@code sourceRoot} itself is trusted (as "this is where THIS request's checkout lives"), never
     * anything reachable through it via a symlink:
     * <ul>
     *   <li>{@code sourceRoot} is resolved to its real path once, at the start of the call; it must
     *       already exist as a real directory.
     *   <li>Every visited entry - whether or not it ends in {@code .tf} - is rejected outright if it
     *       is itself a symlink ({@link Files#isSymbolicLink}), BEFORE any name/extension check.
     *       {@link Files#walkFileTree} does not follow symlinks by default, but critically it still
     *       delivers a symlinked directory to {@code visitFile} (never {@code preVisitDirectory})
     *       rather than silently skipping it, so checking for a symlink unconditionally - not just
     *       on {@code .tf}-named entries - is what catches an ancestor-directory symlink escape like
     *       {@code repo/subdir -> /outside}, not only a direct leaf symlink like
     *       {@code repo/evil.tf -> /outside/secret}.
     *   <li>Every {@code .tf} file's real path must still fall under {@code sourceRoot}'s real path,
     *       and must be a genuine regular file.
     *   <li>Individual file size and the running aggregate across the whole tree are both bounded
     *       (constructor-supplied limits) - repository content must not be given an unbounded local
     *       resource-exhaustion path via {@code fmt -recursive}.
     * </ul>
     * The WHOLE staging attempt is rejected atomically on the first violation of any of the above -
     * never a partial result mixing some trusted staged files with some skipped/rejected ones. Each
     * accepted file is staged via {@link #stageTerraformConfigFile} (content-addressed destination
     * filename - the original repository-relative path/name is never used as, or to derive, the
     * destination path).
     *
     * <p><b>Not yet wired into {@link ControlledRunner}</b>: the current {@code TERRAFORM_FMT_CHECK}
     * pipeline stages a single pre-resolved artifact blob via {@link RunnerArtifactStore}/
     * {@link #stageTerraformConfigFile}, which involves no filesystem traversal of repository
     * content at all and is not vulnerable to the symlink-escape scenario this method defends
     * against. This method is the safe, fully-tested primitive a future phase would use once it
     * introduces an actual "repository checkout root" concept into the request pipeline - see
     * {@code docs/phase-2b3-controlled-terraform-process.md} for the full reasoning.
     */
    public TerraformConfigStagingResult stageTerraformConfigDirectory(
            Path sourceRoot, Path workspace, long maxIndividualFileBytes, long maxAggregateBytes) {
        if (sourceRoot == null) {
            throw new IllegalArgumentException("sourceRoot is required");
        }
        if (maxIndividualFileBytes <= 0 || maxAggregateBytes <= 0) {
            throw new IllegalArgumentException("size bounds must be positive");
        }
        Path sourceRootReal;
        try {
            sourceRootReal = sourceRoot.toRealPath();
        } catch (IOException e) {
            return TerraformConfigStagingResult.failure(RunnerReasonCode.TERRAFORM_CONFIG_SOURCE_UNSAFE);
        }
        List<Path> stagedFiles = new ArrayList<>();
        long[] aggregateBytes = {0L};
        try {
            Files.walkFileTree(sourceRootReal, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    if (Files.isSymbolicLink(file)) {
                        throw new UnsafeConfigSourceException();
                    }
                    if (!file.getFileName().toString().endsWith(".tf")) {
                        return FileVisitResult.CONTINUE;
                    }
                    Path real = file.toRealPath();
                    if (!real.startsWith(sourceRootReal) || !Files.isRegularFile(real)) {
                        throw new UnsafeConfigSourceException();
                    }
                    long size = Files.size(real);
                    if (size > maxIndividualFileBytes) {
                        throw new ConfigSizeLimitException();
                    }
                    aggregateBytes[0] += size;
                    if (aggregateBytes[0] > maxAggregateBytes) {
                        throw new ConfigSizeLimitException();
                    }
                    byte[] content = Files.readAllBytes(real);
                    stagedFiles.add(stageTerraformConfigFile(workspace, contentSha256Hex(content), content));
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (UnsafeConfigSourceException e) {
            return TerraformConfigStagingResult.failure(RunnerReasonCode.TERRAFORM_CONFIG_SOURCE_UNSAFE);
        } catch (ConfigSizeLimitException e) {
            return TerraformConfigStagingResult.failure(RunnerReasonCode.TERRAFORM_CONFIG_SIZE_LIMIT_EXCEEDED);
        } catch (IOException | RunnerWorkspaceException e) {
            return TerraformConfigStagingResult.failure(RunnerReasonCode.TERRAFORM_CONFIG_SOURCE_UNSAFE);
        }
        return TerraformConfigStagingResult.success(stagedFiles);
    }

    /**
     * Phase 2B-4: creates a runner-owned Terraform CLI config file plus its plugin cache directory
     * inside {@code workspace}, so {@code TF_CLI_CONFIG_FILE}/{@code TF_PLUGIN_CACHE_DIR} (see
     * {@link TerraformInitProcessEnvironmentPolicy}) always point at something this trusted code
     * actually created, never at a caller/repository-influenced path. The generated config is
     * deliberately minimal - a plugin cache directory declaration and
     * {@code disable_checkpoint = true} - never a {@code credentials}/{@code provider_installation}
     * block naming any host or path outside the workspace.
     */
    public Path prepareTerraformCliConfig(Path workspace) {
        try {
            Path pluginCache = workspace.resolve("plugin-cache");
            Files.createDirectories(pluginCache);
            requireUnderRoot(pluginCache.toRealPath(), rootDirectory.toRealPath());
            Path cliConfig = workspace.resolve("terraform.rc");
            String escapedPluginCachePath = pluginCache.toString().replace("\\", "\\\\").replace("\"", "\\\"");
            String content = "plugin_cache_dir = \"" + escapedPluginCachePath + "\"\ndisable_checkpoint = true\n";
            Files.writeString(cliConfig, content);
            return cliConfig;
        } catch (IOException e) {
            throw new RunnerWorkspaceException("failed to prepare Terraform CLI config in workspace " + workspace, e);
        }
    }

    private static final class UnsafeConfigSourceException extends IOException {
    }

    private static final class ConfigSizeLimitException extends IOException {
    }

    private static String contentSha256Hex(byte[] content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(content));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available on any supported JVM", e);
        }
    }

    /**
     * Phase 2B-3: re-verifies a previously-created workspace still resolves safely under the
     * configured root, immediately before a Terraform process launch - the TOCTOU discipline
     * established for identity/executable trust in Phase 2B-2/2B-3 applies equally to the working
     * directory a process is about to be launched in, rather than relying solely on the check
     * {@link #createWorkspace} performed possibly minutes earlier in the same request's pipeline.
     */
    public Path revalidate(Path workspace) {
        try {
            Path real = workspace.toRealPath();
            requireUnderRoot(real, rootDirectory.toRealPath());
            return real;
        } catch (IOException e) {
            throw new RunnerWorkspaceException("workspace failed pre-launch revalidation: " + workspace, e);
        }
    }

    /**
     * Best-effort recursive removal of one request's workspace, and only that workspace - the
     * path is re-verified to fall under the configured root before anything is deleted, so a
     * caller can never use this to remove an arbitrary directory. Intended to run only after
     * {@link ControlledRunner} has already durably recorded terminal evidence for the request (see
     * the Phase 2B-2 design doc's cleanup-semantics section): a cleanup failure is swallowed here
     * and must never be allowed to alter an already-determined, already-persisted verification
     * result. Returns {@code true} if cleanup fully succeeded, {@code false} on any failure -
     * callers that want to note a failed cleanup do so as their own diagnostic, never by mutating
     * evidence that has already been written.
     */
    public boolean cleanup(Path workspace) {
        try {
            Path real = workspace.toRealPath();
            requireUnderRoot(real, rootDirectory.toRealPath());
            try (var walk = Files.walk(real)) {
                walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                    try {
                        Files.deleteIfExists(p);
                    } catch (IOException ignored) {
                        // best-effort - overall success/failure is reported by the return value
                    }
                });
            }
            return !Files.exists(real);
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    private static void requireUnderRoot(Path candidate, Path root) {
        if (!candidate.startsWith(root)) {
            throw new IllegalStateException("path escaped the configured root directory: " + candidate);
        }
    }

    private static String safeDirectoryName(String runnerRequestId) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(runnerRequestId.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available on any supported JVM", e);
        }
    }

    private void makeReadOnlyBestEffort(Path path) {
        try {
            Set<PosixFilePermission> readOnly = PosixFilePermissions.fromString("r--r--r--");
            Files.setPosixFilePermissions(path, readOnly);
        } catch (UnsupportedOperationException | IOException e) {
            // Non-POSIX filesystem, or insufficient permission to change mode - best-effort only,
            // consistent with the Phase 2A execution contract's own acknowledgment that ordinary
            // filesystem permissions are not a hardware/kernel-level immutability guarantee.
        }
    }

    public static final class RunnerWorkspaceException extends RuntimeException {
        public RunnerWorkspaceException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
