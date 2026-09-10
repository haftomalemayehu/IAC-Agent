package com.iacagent.iacagent;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class Phase1dTests {

    @Test
    void blockedSchemaProducesBlockedDecision() {
        PlanSummary plan = new PlanSummary(1, 0, 0, 0, 0, List.of());
        ReviewDecision decision = ReviewDecisionEngine.determineDecision(RiskLevel.LOW, ValidationState.BLOCKED, ValidationState.PASS, ValidationState.PASS, plan, List.of());
        assertEquals(ReviewDecision.BLOCKED, decision);
    }

    @Test
    void replacementPlanRequiresApproval() {
        PlanSummary plan = new PlanSummary(0, 0, 1, 0, 0, List.of(new ResourceChange("delete_create", "aws_db_instance", "orders", null, "{}", "{}")));
        ReviewDecision decision = ReviewDecisionEngine.determineDecision(RiskLevel.HIGH, ValidationState.PASS, ValidationState.PASS, ValidationState.PASS, plan, List.of("RESOURCE_REPLACEMENT"));
        assertEquals(ReviewDecision.APPROVAL_REQUIRED, decision);
    }

    @Test
    void destructivePlanRequiresApproval() {
        PlanSummary plan = new PlanSummary(0, 0, 0, 1, 0, List.of(new ResourceChange("delete", "aws_s3_bucket", "logs", null, "{}", "{}")));
        ReviewDecision decision = ReviewDecisionEngine.determineDecision(RiskLevel.MEDIUM, ValidationState.PASS, ValidationState.PASS, ValidationState.PASS, plan, List.of());
        assertEquals(ReviewDecision.APPROVAL_REQUIRED, decision);
    }

    @Test
    void prCommentRendererIncludesRequiredSections() {
        PlanSummary plan = new PlanSummary(4, 2, 1, 0, 0, List.of(
                new ResourceChange("delete_create", "aws_db_instance", "orders", null, "{}", "{}"),
                new ResourceChange("create", "aws_iam_policy", "runtime", null, "{}", "{}")
        ));
        PullRequestReview review = PullRequestReview.fromEvidence(
                "sha256:abc",
                plan,
                RiskLevel.HIGH,
                ValidationState.PASS,
                ValidationState.PASS,
                ValidationState.PASS,
                CostDelta.fromCurrentAndProposed(420.0, 507.0),
                List.of("HIGH_RISK", "RESOURCE_REPLACEMENT", "COST_INCREASE_GT_20_PERCENT"),
                List.of("aws_db_instance.orders will be replaced")
        );

        String markdown = GitHubPrCommentRenderer.render(review);
        assertTrue(markdown.contains("Terraform IaC Review"));
        assertTrue(markdown.contains("Decision: APPROVAL_REQUIRED"));
        assertTrue(markdown.contains("### Plan"));
        assertTrue(markdown.contains("### Security"));
        assertTrue(markdown.contains("### Cost"));
        assertTrue(markdown.contains("### Critical changes"));
        assertTrue(markdown.contains("### Approval reasons"));
    }

    @Test
    void costDeltaCalculatesPercentAndAmount() {
        CostDelta delta = CostDelta.fromCurrentAndProposed(420.0, 507.0);
        assertEquals(87.0, delta.deltaAmount(), 0.01);
        assertEquals(20.7, delta.deltaPercent(), 0.1);
    }

    @Test
    void costThresholdTriggersApprovalRequirement() {
        PlanSummary plan = new PlanSummary(2, 0, 0, 0, 0, List.of());
        CostDelta cost = CostDelta.fromCurrentAndProposed(420.0, 507.0);
        PullRequestReview review = PullRequestReview.fromEvidence("sha256:abc", plan, RiskLevel.LOW, ValidationState.PASS, ValidationState.PASS, ValidationState.PASS, cost, List.of(), List.of());
        assertEquals(ReviewDecision.APPROVAL_REQUIRED, review.decision());
        assertTrue(review.reasons().contains("COST_INCREASE_GT_20_PERCENT"));
    }

    @Test
    void securityBlockingFindingProducesBlockedDecision() {
        PlanSummary plan = new PlanSummary(0, 0, 0, 0, 0, List.of());
        ReviewDecision decision = ReviewDecisionEngine.determineDecision(RiskLevel.LOW, ValidationState.PASS, ValidationState.PASS, ValidationState.FAIL, plan, List.of("SECURITY_BLOCKING_FINDING"));
        assertEquals(ReviewDecision.BLOCKED, decision);
    }

    @Test
    void stalePlanHashIsDetected() {
        PullRequestReview review = PullRequestReview.fromEvidence("sha256:abc", new PlanSummary(1, 0, 0, 0, 0, List.of()), RiskLevel.LOW, ValidationState.PASS, ValidationState.PASS, ValidationState.PASS, null, List.of(), List.of());
        assertTrue(review.isStaleAgainst("sha256:def"));
        assertFalse(review.isStaleAgainst("sha256:abc"));
    }

    @Test
    void duplicateCommentUpdateBehaviorIsDeterministic() throws Exception {
        String payload = "[{\"id\":101,\"body\":\"<!-- terraform-review --> existing review\"}]";
        assertEquals("101", GitHubReviewCommentManager.findExistingCommentId(payload));
        assertEquals("update", GitHubReviewCommentManager.nextAction(payload));
        assertEquals("create", GitHubReviewCommentManager.nextAction("[]"));
    }

    @Test
    void infracostJsonParsesIntoCostDelta() {
        String json = """
                {
                  "currentMonthlyCost": 420.0,
                  "proposedMonthlyCost": 507.0
                }
                """;
        CostDelta delta = InfracostCostService.parseJson(json);
        assertEquals(ValidationState.PASS, delta.status());
        assertEquals(20.7, delta.deltaPercent(), 0.1);
    }
}
