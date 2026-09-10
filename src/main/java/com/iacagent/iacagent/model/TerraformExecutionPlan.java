package com.iacagent.iacagent.model;

import java.util.List;

public record TerraformExecutionPlan(
        String planId,
        String repository,
        String branch,
        String workspace,
        String intent,
        List<TerraformChange> changes,
        int riskScore,
        String riskLevel,
        boolean approvalRequired,
        List<GovernanceCheck> guardrails,
        String generatedAt
) {
}
