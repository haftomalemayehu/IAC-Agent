package com.iacagent.iacagent.approval;

/**
 * The privileged, mutation-capable surface for approval state: issue, revoke, and declare
 * supersession. This is the counterpart to {@link ApprovalProvider}, which is deliberately
 * resolve-only.
 *
 * <p>The type split is the enforcement mechanism, not just documentation: a component that is
 * handed a reference typed as {@link ApprovalProvider} has no method to call that could ever
 * create, revoke, or supersede an approval, regardless of what concrete class actually implements
 * it underneath. Consumers that only need to check an approval (the future Phase 2A executor,
 * for example) must only ever be given an {@code ApprovalProvider}-typed reference. Only the
 * trusted approval-issuing context (Phase 2C-1's test/fixture caller today; Phase 2C's real
 * human-approval workflow later) should ever hold a reference typed as {@code ApprovalAuthority}.
 *
 * <p>Every operation here requires a {@link TrustedApprovalContext} - there is no overload that
 * accepts a bare {@code String approvedBy}/{@code revokedBy}, because that string would come from
 * the same untrusted call site as everything else and could not be distinguished from a forged
 * identity.
 */
public interface ApprovalAuthority {

    /** Issues a brand-new, ACTIVE approval and returns only its id. */
    String issue(ApprovalIssuanceRequest request, TrustedApprovalContext context);

    /** Atomic ACTIVE -&gt; REVOKED transition, attributed to the given trusted principal. */
    TransitionOutcome revoke(String approvalId, TrustedApprovalContext context, String reason);

    /**
     * Issues a new approval that the trusted caller explicitly declares supersedes
     * {@code priorApprovalId}. See {@link ApprovalRecordProducer} for why this is
     * caller-declared rather than automatically discovered by a same-change-context key.
     */
    SupersedingIssuanceResult issueSuperseding(ApprovalIssuanceRequest newRequest, TrustedApprovalContext context, String priorApprovalId);
}
