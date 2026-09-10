package com.iacagent.iacagent.model;

import jakarta.validation.constraints.NotBlank;

public record ApprovalRequest(
        @NotBlank(message = "Plan ID is required") String planId,
        boolean approved,
        String approver,
        String reason
) {
}
