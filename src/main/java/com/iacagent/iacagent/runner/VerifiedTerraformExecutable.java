package com.iacagent.iacagent.runner;

import java.nio.file.Path;
import java.time.Instant;

/**
 * A short-lived, immutable attestation that a specific executable (identified by its real path AND
 * its observed content hash) has been confirmed to report the expected Terraform version.
 * Produced and consumed only by {@link ControlledTerraformOperationCoordinator}, which treats it as
 * valid ONLY for as long as a freshly-recomputed hash of the file at {@link #realPath()} still
 * equals {@link #observedSha256()} - the moment those diverge (the binary was replaced), this
 * attestation is stale and a fresh one must be established by actually invoking
 * {@code terraform version -json} again. This is what lets {@code TERRAFORM_FMT_CHECK}/
 * {@code TERRAFORM_SHOW_PLAN_JSON} bind to a verified Terraform version without launching a
 * redundant {@code version} process before every single call, while still never trusting a version
 * claim for a binary whose content has since changed.
 */
public record VerifiedTerraformExecutable(
        Path realPath,
        String observedSha256,
        String observedVersion,
        Instant verifiedAt
) {
    public VerifiedTerraformExecutable {
        if (realPath == null) {
            throw new IllegalArgumentException("realPath is required");
        }
        if (observedSha256 == null || observedSha256.isBlank()) {
            throw new IllegalArgumentException("observedSha256 is required");
        }
        if (observedVersion == null || observedVersion.isBlank()) {
            throw new IllegalArgumentException("observedVersion is required");
        }
        if (verifiedAt == null) {
            throw new IllegalArgumentException("verifiedAt is required");
        }
    }
}
