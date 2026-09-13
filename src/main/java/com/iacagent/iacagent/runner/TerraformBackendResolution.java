package com.iacagent.iacagent.runner;

import java.nio.file.Path;

/**
 * The trusted output of {@link TrustedBackendResolver#resolve} - a {@link TerraformStateIdentity}
 * plus enough concrete configuration for the coordinator to write a runner-owned backend
 * declaration into the workspace. {@code localStatePath} is the reference/Phase 2B-5 shape (a real
 * Terraform {@code local} backend, chosen because it requires no cloud credentials - see
 * {@code docs/phase-2b5-controlled-plan-state-read.md} for why this is an honest, disclosed
 * reference implementation and not a claim that Gate F is closed). A future resolver for a real
 * remote backend (S3/GCS/azurerm/Terraform Cloud) would extend this shape with whatever concrete
 * fields that backend type needs - never a caller-suppliable free-form config map.
 */
public record TerraformBackendResolution(TerraformStateIdentity stateIdentity, Path localStatePath) {
    public TerraformBackendResolution {
        if (stateIdentity == null) {
            throw new IllegalArgumentException("stateIdentity is required");
        }
        if (localStatePath == null) {
            throw new IllegalArgumentException("localStatePath is required");
        }
    }
}
