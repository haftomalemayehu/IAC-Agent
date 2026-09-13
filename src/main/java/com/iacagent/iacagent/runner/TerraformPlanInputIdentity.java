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
 * Binds EVERY semantic input a {@code TERRAFORM_PLAN} attempt depends on into one
 * {@code planInputSha256} - the identity that determines whether two plan attempts are asking the
 * same question of Terraform. Same version-prefixed, length-prefixed, unambiguous encoding
 * discipline as {@link RunnerRequest#fingerprintSha256()}/{@link TerraformConfigIdentity}/
 * {@link TerraformStateIdentity} - no delimiter, no ambiguous concatenation.
 *
 * <p>Variable inputs are sorted by name (canonical ordering, never insertion order) before hashing,
 * and duplicate names are rejected - the same discipline {@link TerraformConfigIdentity} applies to
 * file entries. A variable's {@code sensitive} flag is itself part of the encoded bytes (so
 * flipping it changes identity) but the raw {@code canonicalJsonValue} bytes are hashed the same way
 * regardless - a hash never reveals the value, so there is no tension with never persisting a
 * sensitive value in evidence.
 */
final class TerraformPlanInputIdentity {

    private static final int ENCODING_VERSION = 1;

    private TerraformPlanInputIdentity() {
    }

    static String computeSha256(
            String configSha256,
            String stateIdentitySha256,
            String providerLockHashExpected,
            String executableSha256Expected,
            String terraformVersionExpected,
            String environment,
            String executionMode,
            List<TerraformVariableInput> variableInputs
    ) {
        List<TerraformVariableInput> sortedVariables = variableInputs.stream()
                .sorted(Comparator.comparing(TerraformVariableInput::name))
                .toList();
        for (int i = 1; i < sortedVariables.size(); i++) {
            if (sortedVariables.get(i - 1).name().equals(sortedVariables.get(i).name())) {
                throw new IllegalArgumentException("duplicate variable name in plan input identity: " + sortedVariables.get(i).name());
            }
        }
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            writeInt(buffer, ENCODING_VERSION);
            writeLengthPrefixed(buffer, configSha256);
            writeLengthPrefixed(buffer, stateIdentitySha256);
            writeLengthPrefixed(buffer, providerLockHashExpected);
            writeLengthPrefixed(buffer, executableSha256Expected);
            writeLengthPrefixed(buffer, terraformVersionExpected);
            writeLengthPrefixed(buffer, environment);
            writeLengthPrefixed(buffer, executionMode);
            writeInt(buffer, sortedVariables.size());
            for (TerraformVariableInput variable : sortedVariables) {
                writeLengthPrefixed(buffer, variable.name());
                writeLengthPrefixed(buffer, variable.canonicalJsonValue());
                buffer.write(variable.sensitive() ? 1 : 0);
            }
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(buffer.toByteArray()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available on any supported JVM", e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void writeLengthPrefixed(ByteArrayOutputStream buffer, String value) throws IOException {
        byte[] bytes = (value == null ? "" : value).getBytes(StandardCharsets.UTF_8);
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
