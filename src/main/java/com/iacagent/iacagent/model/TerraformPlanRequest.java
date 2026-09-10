package com.iacagent.iacagent.model;

import jakarta.validation.constraints.NotBlank;

import java.util.List;

public record TerraformPlanRequest(
        @NotBlank(message = "Repository is required") String repository,
        @NotBlank(message = "Branch is required") String branch,
        @NotBlank(message = "Workspace is required") String workspace,
        @NotBlank(message = "Intent is required") String intent,
        List<TerraformChange> changes,
        boolean autoApprove
) {
}
