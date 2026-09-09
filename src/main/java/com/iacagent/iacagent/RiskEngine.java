package com.iacagent.iacagent;

public class RiskEngine {
    public RiskAssessment assess(PlanSummary summary, String environment) {
        if (summary == null) {
            return new RiskAssessment(0, RiskLevel.LOW, DeploymentEligibility.BLOCKED, "No plan summary available");
        }

        int score = summary.create() * 1 + summary.update() * 2 + summary.replace() * 5 + summary.destroy() * 8;
        for (ResourceChange change : summary.changes()) {
            String type = change.resourceType() == null ? "" : change.resourceType().toLowerCase();
            if (type.contains("iam")) {
                score += 3;
            }
            if (type.contains("network") || type.contains("security_group") || type.contains("acl")) {
                score += 4;
            }
            if (type.contains("database") || type.contains("db_")) {
                score += 5;
            }
            if (type.contains("kms")) {
                score += 5;
            }
            if (type.contains("kubernetes") || type.contains("eks")) {
                score += 5;
            }
            if (type.contains("state") || type.contains("s3") && change.action().contains("destroy")) {
                score += 10;
            }
        }

        if (environment != null && environment.toLowerCase().contains("prod")) {
            score *= 2;
        }

        RiskLevel level = score <= 5 ? RiskLevel.LOW : score <= 15 ? RiskLevel.MEDIUM : score <= 30 ? RiskLevel.HIGH : RiskLevel.CRITICAL;
        DeploymentEligibility deploymentEligibility = (score >= 16 || summary.replace() > 0 || summary.destroy() > 0)
                ? DeploymentEligibility.APPROVAL_REQUIRED
                : DeploymentEligibility.ELIGIBLE;

        String summaryText = "Score=" + score + ", level=" + level + ", eligibility=" + deploymentEligibility;
        return new RiskAssessment(score, level, deploymentEligibility, summaryText);
    }
}
