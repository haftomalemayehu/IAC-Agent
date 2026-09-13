package com.iacagent.iacagent.runner;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * The Phase 2B-5 reference {@link TrustedBackendResolver}: deterministically maps
 * {@code (repository, environment)} to a genuine Terraform {@code local} backend instance, rooted
 * under a single trusted {@code stateRoot} directory this class owns - never a caller-suppliable
 * path. Chosen specifically because the {@code local} backend needs no cloud credentials at all
 * (state read/write and locking are real, ordinary local-filesystem operations), which lets Phase
 * 2B-5 exercise a genuinely real state-read boundary (backend init, state read, plan-time lock
 * acquire/release) without requiring the production workload identity Gate C still calls for.
 *
 * <p><b>This is explicitly a reference/non-production implementation - not a claim that Gate F
 * (production remote-state/backend hardening) is closed.</b> A production resolver for a real
 * remote backend (S3/GCS/azurerm/Terraform Cloud) would need real backend HA/failure handling,
 * backend credential brokering, and a governed backend-mapping authority beyond what a single local
 * directory can represent - see {@code docs/phase-2b5-controlled-plan-state-read.md} §16 (Gate F).
 *
 * <p>{@code canonicalStateKey} is a SHA-256 over the SAME version-prefixed, length-prefixed encoding
 * discipline used throughout this package - the same {@code (repository, environment)} pair always
 * produces the same key; different pairs practically never collide.
 */
public final class ReferenceLocalBackendResolver implements TrustedBackendResolver {

    /** Fixed for this reference resolver - there is only ever one trusted backend "instance" (this
     * host's local filesystem, rooted at {@code stateRoot}), so there is nothing else to name here.
     * A production resolver would compute this from real backend/account/project identity instead. */
    private static final String REFERENCE_BACKEND_INSTANCE_ID = "reference-local";

    private final Path stateRoot;

    public ReferenceLocalBackendResolver(Path stateRoot) {
        if (stateRoot == null) {
            throw new IllegalArgumentException("stateRoot is required");
        }
        this.stateRoot = stateRoot.toAbsolutePath().normalize();
    }

    @Override
    public TerraformBackendResolution resolve(String repository, String environment) {
        if (repository == null || repository.isBlank()) {
            throw new IllegalArgumentException("repository is required");
        }
        if (environment == null || environment.isBlank()) {
            throw new IllegalArgumentException("environment is required");
        }
        String canonicalStateKey = canonicalStateKeyFor(repository, environment);
        TerraformStateIdentity stateIdentity = new TerraformStateIdentity("local", REFERENCE_BACKEND_INSTANCE_ID, environment, canonicalStateKey);
        Path statePath = stateRoot.resolve(canonicalStateKey).resolve("terraform.tfstate");
        return new TerraformBackendResolution(stateIdentity, statePath);
    }

    private static String canonicalStateKeyFor(String repository, String environment) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            writeInt(buffer, 1);
            writeLengthPrefixed(buffer, repository);
            writeLengthPrefixed(buffer, environment);
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
