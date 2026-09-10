package com.iacagent.iacagent.approval;

/**
 * Evidence establishing where an approval's authority came from. Fields are references, not
 * approval authority themselves - a PR reference or CI run URL is audit context, never a
 * substitute for the approvedBy/approvedAt/status fields on ApprovalRecord.
 */
public record ApprovalProvenance(
        String reviewedPrReference,
        String ciRunReference
) {
    public static final ApprovalProvenance NONE = new ApprovalProvenance(null, null);
}
