package com.iacagent.iacagent.approval;

/**
 * {@code resolvedRecord} is populated whenever an ApprovalRecord was found (including for every
 * mismatch/invalid outcome), and is null only for {@link ApprovalValidationReasonCode#APPROVAL_NOT_FOUND} -
 * there was nothing to resolve.
 */
public record ApprovalValidationResult(
        ApprovalValidationReasonCode reasonCode,
        ApprovalRecord resolvedRecord
) {
    public boolean isValid() {
        return reasonCode == ApprovalValidationReasonCode.VALID;
    }

    public static ApprovalValidationResult of(ApprovalValidationReasonCode reasonCode, ApprovalRecord resolvedRecord) {
        return new ApprovalValidationResult(reasonCode, resolvedRecord);
    }
}
