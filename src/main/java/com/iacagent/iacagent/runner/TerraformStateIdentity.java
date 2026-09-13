package com.iacagent.iacagent.runner;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * The canonical identity of the Terraform state a {@code TERRAFORM_PLAN} attempt reads - never
 * derived from anything a {@link RunnerRequest} or repository content supplies, only from
 * {@link TrustedBackendResolver#resolve}'s trusted output. The same {@code (repository, environment)}
 * pair must always resolve to the same identity; two different pairs must never collide.
 *
 * <p>Deliberately carries no credential material - {@code canonicalBackendInstanceId}/
 * {@code canonicalStateKey} name WHICH state is being read, never how to authenticate to it.
 */
public record TerraformStateIdentity(
        String backendType,
        String canonicalBackendInstanceId,
        String environment,
        String canonicalStateKey
) {
    private static final int ENCODING_VERSION = 1;

    public TerraformStateIdentity {
        require(backendType, "backendType");
        require(canonicalBackendInstanceId, "canonicalBackendInstanceId");
        require(environment, "environment");
        require(canonicalStateKey, "canonicalStateKey");
    }

    private static void require(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
    }

    /** Same version-prefixed, length-prefixed, unambiguous encoding discipline as
     * {@link RunnerRequest#fingerprintSha256()}/{@link TerraformConfigIdentity} - no delimiter that
     * any of these fields (in principle attacker-influenced via repository/environment naming) could
     * be crafted to collide across. */
    public String sha256Hex() {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            writeInt(buffer, ENCODING_VERSION);
            writeLengthPrefixed(buffer, backendType);
            writeLengthPrefixed(buffer, canonicalBackendInstanceId);
            writeLengthPrefixed(buffer, environment);
            writeLengthPrefixed(buffer, canonicalStateKey);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(buffer.toByteArray()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available on any supported JVM", e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void writeLengthPrefixed(ByteArrayOutputStream buffer, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
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
