package com.iacagent.iacagent.model;

import jakarta.validation.constraints.NotBlank;

public record TerraformExecutionRequest(
        @NotBlank(message = "Plan ID is required") String planId,
        boolean approved,
        boolean autoApprove,
        String executor,
        String workspace
) {
}
