package com.iacagent.iacagent;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class Phase1eTests {

    private PullRequestReview eligibleReview(String planHash) {
        PlanSummary plan = new PlanSummary(2, 1, 0, 0, 0, List.of());
        return PullRequestReview.fromEvidence(
                planHash,
                plan,
                RiskLevel.LOW,
                ValidationState.PASS,
                ValidationState.PASS,
                ValidationState.PASS,
                CostDelta.notRun("Infracost not executed"),
                List.of(),
                List.of()
        );
    }

    @Test
    void markdownWithRunLinkIncludesCiRunReference() {
        PullRequestReview review = eligibleReview("sha256:aaa");
        String markdown = review.markdown("https://github.com/acme/repo/actions/runs/123", null);
        assertTrue(markdown.contains("https://github.com/acme/repo/actions/runs/123"));
        assertTrue(markdown.contains("### Evidence"));
    }

    @Test
    void markdownNotesWhenSupersedingAStalePriorReview() {
        PullRequestReview review = eligibleReview("sha256:bbb");
        String markdown = review.markdown("https://github.com/acme/repo/actions/runs/124", "sha256:aaa");
        assertTrue(markdown.contains("sha256:aaa"), "should reference the superseded plan hash");
        assertTrue(markdown.toLowerCase().contains("supersede") || markdown.toLowerCase().contains("stale"));
    }

    @Test
    void markdownDoesNotMentionStalenessWhenHashUnchanged() {
        PullRequestReview review = eligibleReview("sha256:ccc");
        String markdown = review.markdown("https://github.com/acme/repo/actions/runs/125", "sha256:ccc");
        assertFalse(markdown.toLowerCase().contains("supersede"));
    }

    @Test
    void blockedDecisionRendersBlockedLiterally() {
        PlanSummary plan = new PlanSummary(1, 0, 0, 0, 0, List.of());
        PullRequestReview review = PullRequestReview.fromEvidence(
                "sha256:ddd", plan, RiskLevel.LOW,
                ValidationState.PASS, ValidationState.FAIL, ValidationState.PASS,
                CostDelta.notRun("n/a"), List.of(), List.of()
        );
        assertEquals(ReviewDecision.BLOCKED, review.decision());
        assertTrue(review.markdown().contains("Decision: BLOCKED"));
    }
}
