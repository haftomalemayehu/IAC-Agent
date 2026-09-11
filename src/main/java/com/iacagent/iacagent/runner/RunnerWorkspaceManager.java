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
 * never interpolated into a path.
 *
 * <p>Isolation guarantees this class provides: a fresh directory per {@code runnerRequestId}
 * (never reused, never shared with another request), an atomic write-then-rename into a
 * content-addressed filename (no partially-written file is ever visible at that path), and
 * best-effort read-only permissions on the staged file once written. What it deliberately does
 * NOT do in Phase 2B-1: invoke any process inside the workspace, set or inherit any environment
 * variable, or resolve any executable/PATH - there is no execution surface here to isolate yet.
 * Those isolation properties (bounded environment variables, no inherited shell environment, no
 * ambient cloud credentials) become meaningful once a later 2B slice actually invokes a process,
 * and are recorded as deferred in the Phase 2B-1 design doc rather than claimed here.
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
            // Defense in depth: the hash-derived name cannot structurally escape rootDirectory,
            // but this is verified explicitly rather than assumed, matching the Phase 2A execution
            // contract's own preference for a redundant check at the point of use.
            if (!workspace.startsWith(rootDirectory)) {
                throw new IllegalStateException("computed workspace path escaped the configured root directory");
            }
            Files.createDirectories(workspace);
            return workspace;
        } catch (IOException e) {
            throw new RunnerWorkspaceException("failed to create workspace for the given request", e);
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

    /**
     * Stages {@code content} into {@code workspace} under a content-addressed filename, using
     * write-to-temp-then-atomic-rename so the final path never shows a partially-written file,
     * then marks it read-only to the extent the host filesystem's permission model supports.
     */
    public Path stageArtifact(Path workspace, String sha256Hex, byte[] content) {
        try {
            Path target = workspace.resolve("sha256-" + sha256Hex + ".tfplan");
            Path temp = Files.createTempFile(workspace, "staging-", ".tmp");
            Files.write(temp, content);
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            makeReadOnlyBestEffort(target);
            return target;
        } catch (IOException e) {
            throw new RunnerWorkspaceException("failed to stage artifact into workspace " + workspace, e);
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
