package com.iacagent.iacagent;

public record RiskAssessment(
        int score,
        RiskLevel level,
        DeploymentEligibility deploymentEligibility,
        String summary
) {
}
