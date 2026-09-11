package com.iacagent.iacagent.runner;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * The typed, caller-supplied request contract. Deliberately carries no runner-identity field of
 * any kind (no runnerId, no "trusted" flag, no environment-scope claim) - identity is resolved
 * exclusively from {@link RunnerIdentityProvider}, a dependency of {@link ControlledRunner} that
 * the caller cannot reach or influence. A caller who wants to see this enforced can inspect this
 * type's record components directly: there is nothing to spoof because there is nowhere to put it.
 *
 * <p>Also carries no raw command/shell string - {@code requestedOperation} is the closed
 * {@link RunnerOperation} enum, not free text, and no field here is ever interpreted as an
 * executable, an argument list, or a URL to fetch.
 */
public record RunnerRequest(
        String runnerRequestId,
        String repository,
        String commitSha,
        String environment,
        String planArtifactId,
        String planSha256,
        String terraformVersion,
        String providerLockHash,
        String approvalId,
        RunnerOperation requestedOperation
) {
    /**
     * Bumped only if the encoding below ever changes shape (field order, field set, or the
     * length-prefix format itself) - included in the hashed bytes so that a future encoding change
     * can never accidentally produce a fingerprint collision with a value computed under the old
     * encoding, even if the field values themselves happen to coincide.
     */
    private static final int FINGERPRINT_ENCODING_VERSION = 1;

    public RunnerRequest {
        require(runnerRequestId, "runnerRequestId");
        require(repository, "repository");
        require(commitSha, "commitSha");
        require(environment, "environment");
        require(planArtifactId, "planArtifactId");
        require(planSha256, "planSha256");
        require(terraformVersion, "terraformVersion");
        require(providerLockHash, "providerLockHash");
        require(approvalId, "approvalId");
        if (requestedOperation == null) {
            throw new IllegalArgumentException("requestedOperation is required");
        }
    }

    private static void require(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
    }

    /**
     * A deterministic, restart-stable fingerprint of everything about this request EXCEPT
     * {@code runnerRequestId} itself (the id is the ledger key; the fingerprint is "what was
     * requested under that key"). Deliberately SHA-256 over a canonical byte encoding, not
     * {@code hashCode()} - a record's generated {@code hashCode()} is not guaranteed stable across
     * JVM restarts for enum-typed fields (enum hashCode is identity-based unless overridden), which
     * would silently break restart-durable duplicate detection.
     *
     * <p>This fingerprint is a security/authorization invariant - {@code runnerRequestId +
     * fingerprint} is what distinguishes a genuine resubmission from a different request attempting
     * to reuse the same id (see {@link ControlledRunner#execute}) - so the encoding fed to SHA-256
     * must be unambiguous: no two distinct field tuples may ever produce the same byte sequence. An
     * earlier revision joined fields with a single NUL character as a separator; that is NOT safe,
     * because these fields are untrusted and a Java {@code String} can itself contain a NUL
     * character. For example {@code repository="a", commitSha="b\0c"} and
     * {@code repository="a\0b", commitSha="c"} (with every other field identical) produce the exact
     * same NUL-joined string, and therefore the exact same hash under a delimiter-based scheme - a
     * cryptographic hash cannot repair ambiguity that already exists in the bytes being hashed.
     *
     * <p>The encoding here is version-prefixed, length-prefixed UTF-8 fields instead: each field is
     * preceded by its own 4-byte big-endian byte-length, so no field's content - NUL, any other
     * delimiter candidate, or arbitrary control/adversarial bytes - can ever be misread as a field
     * boundary. Two different field-tuples can only produce the same encoded bytes by having every
     * field, including every length prefix, identical - i.e. by actually being the same request.
     */
    public String fingerprintSha256() {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            writeInt(buffer, FINGERPRINT_ENCODING_VERSION);
            writeLengthPrefixed(buffer, repository);
            writeLengthPrefixed(buffer, commitSha);
            writeLengthPrefixed(buffer, environment);
            writeLengthPrefixed(buffer, planArtifactId);
            writeLengthPrefixed(buffer, planSha256);
            writeLengthPrefixed(buffer, terraformVersion);
            writeLengthPrefixed(buffer, providerLockHash);
            writeLengthPrefixed(buffer, approvalId);
            writeLengthPrefixed(buffer, requestedOperation.name());

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(buffer.toByteArray()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available on any supported JVM", e);
        } catch (IOException e) {
            // ByteArrayOutputStream#write never actually throws IOException in practice, but the
            // method signature declares it - surfaced as unchecked rather than adding a throws
            // clause to a method with no other checked-exception caller in this codebase.
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
