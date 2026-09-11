package com.iacagent.iacagent.runner;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.HexFormat;
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
