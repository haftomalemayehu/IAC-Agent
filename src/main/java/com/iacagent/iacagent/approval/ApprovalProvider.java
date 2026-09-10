package com.iacagent.iacagent.approval;

import java.util.Optional;

/**
 * The consumer-facing resolution boundary, per docs/phase-2a-execution-contract.md SS4's
 * "ApprovalProvider - the only source of approval truth": {@code resolve(approvalId)}. This is
 * the ONLY operation exposed to consumers that merely need to check an approval - contrast with
 * {@link ApprovalAuthority} (issue/revoke/supersede), which only the trusted approval-issuing
 * context should ever be handed a reference to.
 *
 * <p>This is an enforcement boundary, not just a naming convention: a consumer coded against the
 * {@code ApprovalProvider} type - the future Phase 2A executor, for example - has no method to
 * call that could create, revoke, or supersede an approval, regardless of what concrete class
 * implements it underneath. Possession of an {@code approvalId} string must never, by itself,
 * confer mutation authority; only possession of an {@code ApprovalAuthority}-typed reference does.
 *
 * <p>Binding rule: resolution accepts only an approvalId. There is no overload, parameter, or
 * "inline approval" shortcut that accepts caller-supplied approval attributes - doing so would
 * recreate exactly the request-injection forgery threat this boundary exists to close (see
 * docs/phase-2a-threat-model.md SS2 threat 25). A missing/unknown id returns
 * {@link Optional#empty()}, never a default or partially-populated ApprovalRecord.
 */
public interface ApprovalProvider {
    Optional<ApprovalRecord> resolve(String approvalId);
}
