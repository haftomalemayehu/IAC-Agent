package com.iacagent.iacagent.runner;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * The Phase 2B-5 reference {@link TerraformPlanArtifactStore}: one directory per
 * content-addressed {@code planArtifactId} under a trusted root, holding the exact saved-plan bytes
 * (write-to-temp-then-atomic-rename, same discipline as {@link RunnerWorkspaceManager}) plus a
 * hand-written JSON metadata sidecar (this codebase's established convention - see
 * {@code TerraformProcessEvidenceJson} - of never relying on Jackson POJO/record data binding for a
 * small, fully-known field set).
 *
 * <p><b>Sensitive-artifact security boundary (Phase 2B-5 security amendment).</b> HashiCorp
 * documents that a saved plan file can contain the full configuration, planned values, plan
 * options, and input variables - including sensitive values in cleartext - and treats both state
 * and plan files as sensitive. This store therefore treats every artifact as a secret:
 * <ul>
 *   <li>a single trusted canonical (real-path-resolved) artifact root is established once, at
 *   construction - never re-derived per call;</li>
 *   <li>every artifact path is derived INTERNALLY - {@code store()} never accepts a caller-supplied
 *   id, and {@code resolve()}/{@code metadata()} validate a caller-supplied {@code planArtifactId}
 *   against a strict {@code sha256-<64 lowercase hex>} pattern BEFORE it is ever resolved to a
 *   filesystem path, so no {@code ..}, absolute path, or path separator in a caller-supplied string
 *   can influence where a lookup reads from;</li>
 *   <li>a symlink anywhere in the artifact directory, plan file, or metadata file position is
 *   rejected outright, both by an explicit {@link Files#isSymbolicLink} check and by a real-path
 *   containment recheck against the trusted root (the same two-step discipline
 *   {@link RunnerWorkspaceManager} already uses for workspace paths);</li>
 *   <li>{@code resolve()} requires both files to be regular files, recomputes the plan's SHA-256
 *   from the bytes it actually read, and rejects (as {@link Optional#empty()} - indistinguishable
 *   from "not found", not a distinguishing exception) if that hash does not match the stored
 *   metadata, if the metadata's own recorded {@code planArtifactId}/{@code planSha256} do not match
 *   the id that was requested, or if the artifact directory name does not match the hash the bytes
 *   actually produce;</li>
 *   <li>writes are atomic (write-to-temp, then {@link StandardCopyOption#ATOMIC_MOVE}) so no
 *   partially-written plan or metadata file is ever visible at its final path;</li>
 *   <li>on POSIX filesystems, the artifact root and every artifact directory are best-effort
 *   restricted to owner-only ({@code 0700}), and both the plan binary and the metadata sidecar
 *   (which carries repository/commit/environment/state-identity identifiers) to owner
 *   read/write-only ({@code 0600}). POSIX support is never mandatory - on a non-POSIX filesystem
 *   these calls no-op (see {@link #restrictDirectoryBestEffort}/{@link #restrictFileBestEffort}),
 *   exactly the same best-effort discipline {@link RunnerWorkspaceManager#makeReadOnlyBestEffort}
 *   already established;</li>
 *   <li>plan bytes and decoded plan content are never placed in a log message, exception message,
 *   {@code RunnerEvidence}, ledger JSON, or artifact metadata - only sizes and hashes are recorded.</li>
 * </ul>
 *
 * <p><b>Explicitly non-production and unencrypted</b> - acceptable per the Phase 2B-5 authorization
 * ("a file-backed durable reference store is acceptable if explicitly non-production"), not a claim
 * that Gate A/B/F's durable-storage requirements are satisfied for plan artifacts. A production
 * store would additionally need encryption-at-rest (e.g. KMS-backed), a real access-control model,
 * and a retention policy - see Gate F in {@code docs/phase-2b5-controlled-plan-state-read.md}. This
 * reference implementation provides none of those; it only prevents this JVM process's own callers
 * from being tricked into reading the wrong, tampered, or maliciously-relocated bytes.
 */
public final class FileBackedTerraformPlanArtifactStore implements TerraformPlanArtifactStore {

    private static final Pattern PLAN_ARTIFACT_ID_PATTERN = Pattern.compile("^sha256-[0-9a-f]{64}$");

    private final Path root;

    public FileBackedTerraformPlanArtifactStore(Path root) {
        if (root == null) {
            throw new IllegalArgumentException("root is required");
        }
        try {
            Path candidate = root.toAbsolutePath().normalize();
            Files.createDirectories(candidate);
            restrictDirectoryBestEffort(candidate);
            this.root = candidate.toRealPath();
        } catch (IOException e) {
            throw new UncheckedIOException("failed to establish trusted plan artifact root " + root, e);
        }
    }

    @Override
    public TerraformPlanArtifactMetadata store(
            String repository, String commitSha, String environment, String stateIdentitySha256, String planInputSha256, byte[] planBytes) {
        if (planBytes == null || planBytes.length == 0) {
            throw new IllegalArgumentException("planBytes must not be empty");
        }
        String planSha256 = sha256Hex(planBytes);
        String planArtifactId = "sha256-" + planSha256;
        TerraformPlanArtifactMetadata metadata = new TerraformPlanArtifactMetadata(
                planArtifactId, planSha256, planInputSha256, repository, commitSha, environment, stateIdentitySha256,
                planBytes.length, Instant.now());
        try {
            Path artifactDir = root.resolve(planArtifactId);
            requireUnderRoot(artifactDir.normalize());
            rejectExistingSymlink(artifactDir);
            Files.createDirectories(artifactDir);
            restrictDirectoryBestEffort(artifactDir);
            requireUnderRoot(artifactDir.toRealPath());

            Path planPath = artifactDir.resolve("plan.tfplan");
            Path metadataPath = artifactDir.resolve("metadata.json");
            rejectExistingSymlink(planPath);
            rejectExistingSymlink(metadataPath);

            writeAtomically(planPath, planBytes);
            restrictFileBestEffort(planPath);
            writeAtomically(metadataPath, toJson(metadata).getBytes(StandardCharsets.UTF_8));
            restrictFileBestEffort(metadataPath);
            return metadata;
        } catch (IOException e) {
            throw new UncheckedIOException("failed to durably store plan artifact " + planArtifactId, e);
        }
    }

    @Override
    public Optional<StoredTerraformPlanArtifact> resolve(String planArtifactId) {
        Path artifactDir = validatedArtifactDir(planArtifactId);
        if (artifactDir == null) {
            return Optional.empty();
        }
        Path metadataPath = artifactDir.resolve("metadata.json");
        Path planPath = artifactDir.resolve("plan.tfplan");
        if (Files.isSymbolicLink(metadataPath) || Files.isSymbolicLink(planPath)) {
            return Optional.empty();
        }
        if (!Files.isRegularFile(metadataPath) || !Files.isRegularFile(planPath)) {
            return Optional.empty();
        }
        try {
            requireUnderRoot(metadataPath.toRealPath());
            requireUnderRoot(planPath.toRealPath());

            TerraformPlanArtifactMetadata metadata = fromJson(Files.readString(metadataPath, StandardCharsets.UTF_8));
            byte[] planBytes = Files.readAllBytes(planPath);
            String actualPlanSha256 = sha256Hex(planBytes);

            // Resolve-time integrity verification: the artifact id, the metadata's own recorded
            // identity, and the bytes actually read must all agree - any disagreement means either
            // on-disk tampering/corruption or a metadata/artifact mismatch, and this store never
            // trusts a lookup it cannot fully verify. Treated identically to "not found" so a
            // caller cannot distinguish "never existed" from "existed but failed verification".
            if (!planArtifactId.equals(metadata.planArtifactId())) {
                return Optional.empty();
            }
            if (!actualPlanSha256.equals(metadata.planSha256())) {
                return Optional.empty();
            }
            if (!planArtifactId.equals("sha256-" + actualPlanSha256)) {
                return Optional.empty();
            }
            return Optional.of(new StoredTerraformPlanArtifact(metadata, planBytes));
        } catch (IllegalStateException | IOException e) {
            // Symlink/containment escape or an unreadable artifact: fail closed as "not found"
            // rather than surfacing a distinguishing exception.
            return Optional.empty();
        }
    }

    @Override
    public Optional<TerraformPlanArtifactMetadata> metadata(String planArtifactId) {
        Path artifactDir = validatedArtifactDir(planArtifactId);
        if (artifactDir == null) {
            return Optional.empty();
        }
        Path metadataPath = artifactDir.resolve("metadata.json");
        if (Files.isSymbolicLink(metadataPath) || !Files.isRegularFile(metadataPath)) {
            return Optional.empty();
        }
        try {
            requireUnderRoot(metadataPath.toRealPath());
            TerraformPlanArtifactMetadata metadata = fromJson(Files.readString(metadataPath, StandardCharsets.UTF_8));
            if (!planArtifactId.equals(metadata.planArtifactId())) {
                return Optional.empty();
            }
            if (!planArtifactId.equals("sha256-" + metadata.planSha256())) {
                return Optional.empty();
            }
            return Optional.of(metadata);
        } catch (IllegalStateException | IOException e) {
            return Optional.empty();
        }
    }

    /**
     * Validates {@code planArtifactId} against the strict content-addressed format BEFORE ever
     * resolving it to a path, then verifies the resulting artifact directory is neither a symlink
     * nor outside the trusted root - the trusted-root-containment and no-traversal/no-symlink
     * defenses required for every caller-supplied lookup key. Returns {@code null} (never throws)
     * on any rejection so callers uniformly treat it as "not found".
     */
    private Path validatedArtifactDir(String planArtifactId) {
        if (planArtifactId == null || !PLAN_ARTIFACT_ID_PATTERN.matcher(planArtifactId).matches()) {
            return null;
        }
        Path artifactDir = root.resolve(planArtifactId).normalize();
        try {
            requireUnderRoot(artifactDir);
        } catch (IllegalStateException e) {
            return null;
        }
        if (Files.isSymbolicLink(artifactDir) || !Files.isDirectory(artifactDir)) {
            return null;
        }
        try {
            requireUnderRoot(artifactDir.toRealPath());
        } catch (IllegalStateException | IOException e) {
            return null;
        }
        return artifactDir;
    }

    private void requireUnderRoot(Path candidate) {
        if (!candidate.startsWith(root)) {
            throw new IllegalStateException("path escaped the trusted plan artifact root: " + candidate);
        }
    }

    private static void rejectExistingSymlink(Path path) {
        if (Files.isSymbolicLink(path)) {
            throw new IllegalStateException("refusing to write through an existing symlink: " + path);
        }
    }

    private void writeAtomically(Path target, byte[] content) throws IOException {
        Path temp = Files.createTempFile(target.getParent(), "staging-", ".tmp");
        try {
            Files.write(temp, content);
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    /** Best-effort {@code 0700} on POSIX filesystems only - never mandatory; a non-POSIX filesystem
     * (or insufficient permission to change mode) silently no-ops, exactly like
     * {@link RunnerWorkspaceManager#makeReadOnlyBestEffort}. */
    private static void restrictDirectoryBestEffort(Path path) {
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"));
        } catch (UnsupportedOperationException | IOException e) {
            // Non-POSIX filesystem, or insufficient permission - best-effort only.
        }
    }

    /** Best-effort {@code 0600} on POSIX filesystems only - never mandatory. */
    private static void restrictFileBestEffort(Path path) {
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException | IOException e) {
            // Non-POSIX filesystem, or insufficient permission - best-effort only.
        }
    }

    private static String toJson(TerraformPlanArtifactMetadata m) {
        return "{"
                + field("planArtifactId", m.planArtifactId()) + ","
                + field("planSha256", m.planSha256()) + ","
                + field("planInputSha256", m.planInputSha256()) + ","
                + field("repository", m.repository()) + ","
                + field("commitSha", m.commitSha()) + ","
                + field("environment", m.environment()) + ","
                + field("stateIdentitySha256", m.stateIdentitySha256()) + ","
                + "\"planByteSize\":" + m.planByteSize() + ","
                + field("storedAt", m.storedAt().toString())
                + "}";
    }

    private static TerraformPlanArtifactMetadata fromJson(String json) {
        tools.jackson.databind.JsonNode root = new tools.jackson.databind.ObjectMapper().readTree(json);
        return new TerraformPlanArtifactMetadata(
                root.path("planArtifactId").asText(),
                root.path("planSha256").asText(),
                root.path("planInputSha256").asText(),
                root.path("repository").asText(),
                root.path("commitSha").asText(),
                root.path("environment").asText(),
                root.path("stateIdentitySha256").asText(),
                root.path("planByteSize").asLong(),
                Instant.parse(root.path("storedAt").asText()));
    }

    private static String field(String name, String value) {
        return quote(name) + ":" + quote(value);
    }

    private static String quote(String value) {
        StringBuilder sb = new StringBuilder(value.length() + 2).append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> sb.append(c);
            }
        }
        return sb.append('"').toString();
    }

    private static String sha256Hex(byte[] content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(content));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available on any supported JVM", e);
        }
    }
}
