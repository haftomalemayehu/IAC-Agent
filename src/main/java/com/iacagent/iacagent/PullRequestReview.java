package com.iacagent.iacagent;

import java.util.ArrayList;
import java.util.List;

public record PullRequestReview(
        ReviewDecision decision,
        RiskLevel risk,
        List<String> reasons,
        String planHash,
        PlanSummary plan,
        ValidationState schema,
        ValidationState validate,
        ValidationState security,
        CostDelta cost,
        List<String> criticalChanges,
        String evidenceReference
) {
    public PullRequestReview {
        if (reasons == null) {
            reasons = List.of();
        } else {
            reasons = List.copyOf(reasons);
        }
        if (criticalChanges == null) {
            criticalChanges = List.of();
        } else {
            criticalChanges = List.copyOf(criticalChanges);
        }
        if (evidenceReference == null || evidenceReference.isBlank()) {
            evidenceReference = "terraform-evidence";
        }
    }

    public static PullRequestReview fromEvidence(
            String planHash,
            PlanSummary plan,
            RiskLevel risk,
            ValidationState schema,
            ValidationState validate,
            ValidationState security,
            CostDelta cost,
            List<String> reasons,
            List<String> criticalChanges
    ) {
        List<String> normalizedReasons = reasons == null ? List.of() : new java.util.ArrayList<>(reasons);
        if (cost != null && cost.deltaPercent() > 20d && !normalizedReasons.contains("COST_INCREASE_GT_20_PERCENT")) {
            normalizedReasons.add("COST_INCREASE_GT_20_PERCENT");
        }
        if (plan != null && plan.replace() > 0 && !normalizedReasons.contains("RESOURCE_REPLACEMENT")) {
            normalizedReasons.add("RESOURCE_REPLACEMENT");
        }
        if (plan != null && plan.destroy() > 0 && !normalizedReasons.contains("RESOURCE_DESTRUCTION")) {
            normalizedReasons.add("RESOURCE_DESTRUCTION");
        }
        if (risk == RiskLevel.HIGH || risk == RiskLevel.CRITICAL) {
            normalizedReasons.add("HIGH_RISK");
        }
        List<String> normalizedCritical = criticalChanges == null ? List.of() : criticalChanges;
        if (normalizedCritical.isEmpty() && plan != null) {
            normalizedCritical = inferCriticalChanges(plan);
        }
        ReviewDecision decision = ReviewDecisionEngine.determineDecision(risk, schema, validate, security, plan, normalizedReasons, cost);
        return new PullRequestReview(decision, risk, normalizedReasons, planHash, plan, schema, validate, security, cost, normalizedCritical, "terraform-evidence");
    }

    public boolean isStaleAgainst(String currentPlanHash) {
        return currentPlanHash == null || planHash == null || !planHash.equals(currentPlanHash);
    }

    public String markdown() {
        return markdown(null, null);
    }

    public String markdown(String ciRunUrl, String priorPlanHash) {
        StringBuilder sb = new StringBuilder();
        sb.append("<!-- terraform-review -->\n");
        sb.append("## Terraform IaC Review\n\n");
        if (priorPlanHash != null && planHash != null && !priorPlanHash.equals(planHash)) {
            sb.append("> **Note:** This review supersedes a stale prior review (plan hash `")
                    .append(priorPlanHash)
                    .append("`). The plan changed since that review; treat only this comment as current.\n\n");
        }
        sb.append("Decision: ").append(decision.name()).append("\n");
        sb.append("Risk: ").append(risk.name()).append("\n\n");

        sb.append("### Plan\n");
        if (plan == null) {
            sb.append("- No plan summary available\n");
        } else {
            sb.append("- create: ").append(plan.create()).append("\n");
            sb.append("- update: ").append(plan.update()).append("\n");
            sb.append("- replace: ").append(plan.replace()).append("\n");
            sb.append("- destroy: ").append(plan.destroy()).append("\n");
        }

        sb.append("\n### Security\n");
        sb.append("- Schema: ").append(schema == null ? ValidationState.NOT_RUN : schema).append("\n");
        sb.append("- Validate: ").append(validate == null ? ValidationState.NOT_RUN : validate).append("\n");
        sb.append("- Security: ").append(security == null ? ValidationState.NOT_RUN : security).append("\n");

        sb.append("\n### Cost\n");
        if (cost == null || cost.status() == ValidationState.NOT_RUN) {
            sb.append("- NOT_RUN").append(cost != null && cost.message() != null ? " (" + cost.message() + ")" : "").append("\n");
        } else if (cost.status() == ValidationState.BLOCKED) {
            sb.append("- BLOCKED (").append(cost.message()).append(")\n");
        } else {
            sb.append("- ").append(cost.deltaPercent() >= 0 ? "+" : "").append(String.format("%.1f", cost.deltaPercent()))
                    .append("% ($").append(String.format("%.2f", cost.currentMonthly()))
                    .append(" -> $").append(String.format("%.2f", cost.proposedMonthly())).append(")\n");
        }

        sb.append("\n### Critical changes\n");
        if (criticalChanges.isEmpty()) {
            sb.append("- None\n");
        } else {
            for (String item : criticalChanges) {
                sb.append("- ").append(item).append("\n");
            }
        }

        sb.append("\n### Approval reasons\n");
        if (reasons.isEmpty()) {
            sb.append("- None\n");
        } else {
            for (String reason : reasons) {
                sb.append("- ").append(reason).append("\n");
            }
        }

        sb.append("\n### Evidence\n");
        sb.append("- Plan hash: ").append(planHash == null ? "sha256:unknown" : planHash).append("\n");
        if (ciRunUrl != null && !ciRunUrl.isBlank()) {
            sb.append("- CI run: ").append(ciRunUrl).append("\n");
        }
        sb.append("- Artifact: ").append(evidenceReference).append("\n");
        return sb.toString();
    }

    private static List<String> inferCriticalChanges(PlanSummary plan) {
        if (plan == null || plan.changes() == null) {
            return List.of();
        }
        List<String> items = new ArrayList<>();
        for (ResourceChange change : plan.changes()) {
            String type = change.resourceType() == null ? "" : change.resourceType().toLowerCase();
            String action = change.action() == null ? "" : change.action();
            if ("replace".equals(action) || "destroy".equals(action) || type.contains("db_instance") || type.contains("iam") || type.contains("kms") || type.contains("security_group") || type.contains("network") || type.contains("public")) {
                items.add((change.resourceType() == null ? "resource" : change.resourceType()) + "." + (change.resourceName() == null ? "unknown" : change.resourceName()) + " requires review");
            }
        }
        return items;
    }
}
