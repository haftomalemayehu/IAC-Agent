package com.iacagent.iacagent.identity;

import com.iacagent.iacagent.runner.RunnerReasonCode;

/** The outcome of {@link WorkloadAuthorizationPolicy#authorize} - mirrors
 * {@link WorkloadIdentityVerificationResult}'s discriminated-result shape. */
public record WorkloadAuthorizationResult(boolean authorized, RunnerReasonCode failureReason) {
    public WorkloadAuthorizationResult {
        if (authorized == (failureReason != null)) {
            throw new IllegalArgumentException("authorized=true must carry no failureReason, and authorized=false must carry one");
        }
    }

    public static WorkloadAuthorizationResult granted() {
        return new WorkloadAuthorizationResult(true, null);
    }

    public static WorkloadAuthorizationResult denied(RunnerReasonCode reason) {
        return new WorkloadAuthorizationResult(false, reason);
    }
}
