package com.iacagent.iacagent.model;

import jakarta.validation.constraints.NotBlank;

public record TerraformApprovalRequest(
        @NotBlank(message = "Plan ID is required") String planId,
        boolean approved,
        String approver,
        String reason
) {
}
