package com.iacagent.iacagent.identity;

import com.iacagent.iacagent.runner.RunnerReasonCode;

/**
 * The outcome of {@link WorkloadIdentityVerifier#verify} - exactly one of {@code identity}/
 * {@code failureReason} is non-null, enforced by the compact constructor, the same discriminated-
 * result discipline {@code com.iacagent.iacagent.approval.ApprovalValidationResult} already
 * establishes in this codebase.
 */
public record WorkloadIdentityVerificationResult(VerifiedWorkloadIdentity identity, RunnerReasonCode failureReason) {
    public WorkloadIdentityVerificationResult {
        if ((identity == null) == (failureReason == null)) {
            throw new IllegalArgumentException("exactly one of identity or failureReason must be set");
        }
    }

    public boolean isValid() {
        return identity != null;
    }

    public static WorkloadIdentityVerificationResult verified(VerifiedWorkloadIdentity identity) {
        return new WorkloadIdentityVerificationResult(identity, null);
    }

    public static WorkloadIdentityVerificationResult rejected(RunnerReasonCode reason) {
        return new WorkloadIdentityVerificationResult(null, reason);
    }
}
