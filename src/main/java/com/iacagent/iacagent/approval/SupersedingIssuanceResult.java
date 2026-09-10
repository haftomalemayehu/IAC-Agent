package com.iacagent.iacagent.approval;

public record SupersedingIssuanceResult(String newApprovalId, TransitionOutcome priorApprovalTransition) {
}
