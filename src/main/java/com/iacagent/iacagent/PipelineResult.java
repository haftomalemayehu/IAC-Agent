package com.iacagent.iacagent;

import java.util.List;
import java.util.Map;

public record PipelineResult(
        String requestId,
        ValidationState validity,
        RiskLevel risk,
        DeploymentEligibility deploymentEligibility,
        Map<String, ValidationState> stages,
        PlanSummary plan,
        ApprovalEngine.ApprovalBinding approval,
        List<String> reasons
) {
}
