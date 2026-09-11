package com.iacagent.iacagent.runner;

/**
 * The result of one {@link TerraformExecutableProvider#resolve()} call. {@code descriptor} is
 * non-null if and only if {@code outcome} is {@link TerraformExecutableResolutionOutcome#RESOLVED} -
 * there is no partially-populated descriptor for a failed resolution.
 */
public record TerraformExecutableResolution(
        TerraformExecutableResolutionOutcome outcome,
        TerraformExecutableDescriptor descriptor
) {
    public TerraformExecutableResolution {
        if (outcome == null) {
            throw new IllegalArgumentException("outcome is required");
        }
        boolean hasDescriptor = descriptor != null;
        boolean shouldHaveDescriptor = outcome == TerraformExecutableResolutionOutcome.RESOLVED;
        if (hasDescriptor != shouldHaveDescriptor) {
            throw new IllegalArgumentException(
                    "descriptor must be present if and only if outcome is RESOLVED: outcome=" + outcome + ", descriptor=" + descriptor);
        }
    }

    static TerraformExecutableResolution resolved(TerraformExecutableDescriptor descriptor) {
        return new TerraformExecutableResolution(TerraformExecutableResolutionOutcome.RESOLVED, descriptor);
    }

    static TerraformExecutableResolution failed(TerraformExecutableResolutionOutcome outcome) {
        if (outcome == TerraformExecutableResolutionOutcome.RESOLVED) {
            throw new IllegalArgumentException("use resolved(descriptor) for a successful resolution");
        }
        return new TerraformExecutableResolution(outcome, null);
    }
}
