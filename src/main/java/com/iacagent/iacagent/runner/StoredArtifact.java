package com.iacagent.iacagent.runner;

/**
 * What {@link RunnerArtifactStore} returns for a known artifact id: the actual bytes, plus the
 * hash the store itself recorded when the artifact was staged/cataloged (independent of anything
 * a {@link RunnerRequest} caller claims). {@link ControlledRunner} never trusts
 * {@code recordedSha256} alone - it always recomputes SHA-256 from {@code content} and compares
 * against both this value (store-internal integrity) and the request's own {@code planSha256}
 * (does this artifact match what the approval actually covers).
 */
public record StoredArtifact(
        String artifactId,
        byte[] content,
        long size,
        String recordedSha256,
        ArtifactProvenance provenance
) {
    public StoredArtifact {
        if (artifactId == null || artifactId.isBlank()) {
            throw new IllegalArgumentException("artifactId is required");
        }
        if (content == null) {
            throw new IllegalArgumentException("content is required");
        }
        if (recordedSha256 == null || recordedSha256.isBlank()) {
            throw new IllegalArgumentException("recordedSha256 is required");
        }
        if (provenance == null) {
            provenance = ArtifactProvenance.NONE;
        }
    }
}
