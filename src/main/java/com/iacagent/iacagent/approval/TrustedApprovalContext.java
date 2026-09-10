package com.iacagent.iacagent.approval;

/**
 * The authenticated approver identity for a privileged {@link ApprovalAuthority} operation
 * (issue/revoke/supersede), supplied separately from the untrusted {@link ApprovalIssuanceRequest}
 * change metadata.
 *
 * <p>This is deliberately its own type rather than a {@code String approvedBy} parameter on the
 * issuance request: a field living inside the same payload that also carries repository/commit/
 * environment/plan data invites a caller to believe they can simply set
 * {@code "approvedBy": "admin"} the way they might set any other field. Requiring a separate,
 * distinctly-named context communicates that this value must come from an authenticated principal
 * source, not from whatever produced the change metadata.
 *
 * <p>In Phase 2C-1 this context is constructed directly by deterministic test/fixture code
 * standing in for a human approver. Phase 2C's authoritative human-approval workflow (GitHub
 * Environment protection / HCP Terraform approval gate) will be the production source of this
 * context's {@code principalId} - this type's shape does not need to change when that happens.
 *
 * <p>Does not carry a timestamp: {@link ApprovalRecordProducer} stamps {@code approvedAt} from its
 * own injected {@link java.time.Clock}, so there is exactly one time authority in the system, not
 * two competing ones.
 */
public record TrustedApprovalContext(String principalId) {
    public TrustedApprovalContext {
        if (principalId == null || principalId.isBlank()) {
            throw new IllegalArgumentException("principalId is required");
        }
    }
}
