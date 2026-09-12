package com.iacagent.iacagent.runner;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;

/**
 * Computes a deterministic {@code configSha256} identity that binds BOTH the relative filename and
 * the content of every staged configuration file (plus the lockfile, if present) - the value
 * {@link TerraformInitEvidence}/{@link TerraformValidateEvidence}/{@link TerraformProviderSchemaEvidence}
 * are all bound to.
 *
 * <p><b>Amended after review:</b> an earlier revision hashed only the multiset of file CONTENTS,
 * sorted by their own bytes - which meant two directory layouts with the same bytes assigned to
 * DIFFERENT filenames could collapse to the identical {@code configSha256}. That is unsafe because
 * Terraform filenames are semantically significant - {@code override.tf}/{@code *_override.tf} have
 * special merge-override behavior, so
 * <pre>
 * A: main.tf = X, override.tf = Y
 * B: main.tf = Y, override.tf = X
 * </pre>
 * are NOT equivalent configurations even though they contain the same two byte sequences, and must
 * never share an identity. This class now hashes canonical (relative path, content) TUPLES, sorted
 * by relative path (never by content) - see {@link #computeSha256}.
 *
 * <p>Uses the same version-prefixed, length-prefixed encoding discipline as
 * {@link RunnerRequest#fingerprintSha256()} - no delimiter that an untrusted relative path or file
 * content could ever be crafted to collide across. Relative paths only are hashed, never absolute
 * workspace paths - two otherwise-identical configurations staged under two different (e.g.
 * randomly-named temp-directory) runner workspace roots must produce the SAME identity.
 */
final class TerraformConfigIdentity {

    private static final int ENCODING_VERSION = 2;

    private TerraformConfigIdentity() {
    }

    /** One staged file's identity: a relative path (e.g. {@code "main.tf"}, {@code "override.tf"},
     * {@code ".terraform.lock.hcl"} - never an absolute path, never a workspace-root-dependent
     * path) and its raw content. */
    record NamedConfigFile(String relativePath, byte[] content) {
        NamedConfigFile {
            if (relativePath == null || relativePath.isBlank()) {
                throw new IllegalArgumentException("relativePath is required");
            }
            if (relativePath.startsWith("/") || relativePath.contains("..")) {
                throw new IllegalArgumentException("relativePath must be a plain relative path, not absolute or containing '..': " + relativePath);
            }
            content = content == null ? new byte[0] : content.clone();
        }

        public byte[] content() {
            return content.clone();
        }
    }

    /**
     * Hashes {@code entries} (every staged {@code *.tf}/{@code *.tf.json} file, plus a
     * {@code ".terraform.lock.hcl"} entry when a lockfile is present) sorted by
     * {@link NamedConfigFile#relativePath()} - never by content, and never including any absolute
     * path. Two entries sharing the same relative path is a caller error (ambiguous input) and is
     * rejected rather than silently resolved by insertion order.
     */
    static String computeSha256(List<NamedConfigFile> entries) {
        List<NamedConfigFile> sorted = entries.stream()
                .sorted(Comparator.comparing(NamedConfigFile::relativePath))
                .toList();
        for (int i = 1; i < sorted.size(); i++) {
            if (sorted.get(i - 1).relativePath().equals(sorted.get(i).relativePath())) {
                throw new IllegalArgumentException("duplicate relative path in configuration identity input: " + sorted.get(i).relativePath());
            }
        }
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            writeInt(buffer, ENCODING_VERSION);
            writeInt(buffer, sorted.size());
            for (NamedConfigFile entry : sorted) {
                writeLengthPrefixed(buffer, entry.relativePath().getBytes(StandardCharsets.UTF_8));
                writeLengthPrefixed(buffer, entry.content());
            }
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(buffer.toByteArray()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available on any supported JVM", e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void writeLengthPrefixed(ByteArrayOutputStream buffer, byte[] bytes) throws IOException {
        writeInt(buffer, bytes.length);
        buffer.write(bytes);
    }

    private static void writeInt(ByteArrayOutputStream buffer, int value) {
        buffer.write((value >>> 24) & 0xFF);
        buffer.write((value >>> 16) & 0xFF);
        buffer.write((value >>> 8) & 0xFF);
        buffer.write(value & 0xFF);
    }
}
