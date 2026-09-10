package com.iacagent.iacagent;

import java.util.List;

public final class ReviewDecisionEngine {
    private ReviewDecisionEngine() {
    }

    public static ReviewDecision determineDecision(
            RiskLevel risk,
            ValidationState schema,
            ValidationState validate,
            ValidationState security,
            PlanSummary plan,
            List<String> reasons
    ) {
        return determineDecision(risk, schema, validate, security, plan, reasons, null);
    }

    public static ReviewDecision determineDecision(
            RiskLevel risk,
            ValidationState schema,
            ValidationState validate,
            ValidationState security,
            PlanSummary plan,
            List<String> reasons,
            CostDelta cost
    ) {
        if (schema == ValidationState.FAIL || schema == ValidationState.BLOCKED) {
            return ReviewDecision.BLOCKED;
        }
        if (validate == ValidationState.FAIL || validate == ValidationState.BLOCKED) {
            return ReviewDecision.BLOCKED;
        }
        if (security == ValidationState.FAIL || security == ValidationState.BLOCKED) {
            return ReviewDecision.BLOCKED;
        }
        if (cost != null && cost.status() == ValidationState.BLOCKED) {
            return ReviewDecision.BLOCKED;
        }
        if (plan == null) {
            return ReviewDecision.BLOCKED;
        }
        if (plan.destroy() > 0 || plan.replace() > 0) {
            return ReviewDecision.APPROVAL_REQUIRED;
        }
        if (risk == RiskLevel.HIGH || risk == RiskLevel.CRITICAL) {
            return ReviewDecision.APPROVAL_REQUIRED;
        }
        if (reasons != null && reasons.stream().anyMatch(reason -> reason.contains("HIGH_RISK")
                || reason.contains("RESOURCE_REPLACEMENT")
                || reason.contains("COST_INCREASE")
                || reason.contains("IAM")
                || reason.contains("NETWORK")
                || reason.contains("DATABASE")
                || reason.contains("KMS"))) {
            return ReviewDecision.APPROVAL_REQUIRED;
        }
        if (cost != null && cost.deltaPercent() > 20d) {
            return ReviewDecision.APPROVAL_REQUIRED;
        }
        if (hasProtectedChange(plan)) {
            return ReviewDecision.APPROVAL_REQUIRED;
        }
        return ReviewDecision.ELIGIBLE;
    }

    private static boolean hasProtectedChange(PlanSummary plan) {
        if (plan == null || plan.changes() == null) {
            return false;
        }
        for (ResourceChange change : plan.changes()) {
            String type = change.resourceType() == null ? "" : change.resourceType().toLowerCase();
            if (type.contains("db_instance") || type.contains("iam") || type.contains("kms") || type.contains("security_group") || type.contains("network") || type.contains("public")) {
                return true;
            }
        }
        return false;
    }
}
