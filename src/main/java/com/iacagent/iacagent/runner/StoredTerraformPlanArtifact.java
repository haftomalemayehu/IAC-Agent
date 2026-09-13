package com.iacagent.iacagent.runner;

/** {@link TerraformPlanArtifactMetadata} plus the exact saved-plan bytes, as returned by
 * {@link TerraformPlanArtifactStore#resolve}. */
public record StoredTerraformPlanArtifact(TerraformPlanArtifactMetadata metadata, byte[] planBytes) {
    public StoredTerraformPlanArtifact {
        if (metadata == null) {
            throw new IllegalArgumentException("metadata is required");
        }
        planBytes = planBytes == null ? new byte[0] : planBytes.clone();
    }

    public byte[] planBytes() {
        return planBytes.clone();
    }
}
