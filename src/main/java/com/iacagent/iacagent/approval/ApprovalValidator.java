package com.iacagent.iacagent.approval;

import java.time.Instant;
import java.util.Optional;

/**
 * Compares an independently resolved, authoritative ApprovalRecord against a requested
 * {@link ExecutionIdentity}. This is the "resolve first, then compare" boundary described in
 * docs/phase-2a-execution-contract.md SS4/SS6: the caller supplies only an approvalId and the
 * identity it wants authorized; this validator never accepts approval attributes directly from
 * a caller, only from the record {@link ApprovalProvider} resolves.
 *
 * <p>Check order: identity mismatches (repository, commit, environment, plan hash) are evaluated
 * before status validity. An approval that doesn't even reference the requested change is a more
 * fundamental problem than whether it happens to still be active, so identity is checked first -
 * mirroring the ordering already locked in docs/phase-2a-execution-contract.md SS6 (identity
 * checks 2-6 precede approval-validity checks 7-9).
 */
public final class ApprovalValidator {

    private ApprovalValidator() {
    }

    public static ApprovalValidationResult validate(ApprovalProvider provider, String approvalId, ExecutionIdentity requested, Instant now) {
        if (provider == null) {
            throw new IllegalArgumentException("provider is required");
        }
        if (requested == null) {
            throw new IllegalArgumentException("requested identity is required");
        }
        if (now == null) {
            throw new IllegalArgumentException("now is required");
        }

        Optional<ApprovalRecord> resolved = approvalId == null || approvalId.isBlank()
                ? Optional.empty()
                : provider.resolve(approvalId);

        if (resolved.isEmpty()) {
            return ApprovalValidationResult.of(ApprovalValidationReasonCode.APPROVAL_NOT_FOUND, null);
        }

        ApprovalRecord record = resolved.get();

        if (!record.repository().equals(requested.repository())) {
            return ApprovalValidationResult.of(ApprovalValidationReasonCode.REPOSITORY_MISMATCH, record);
        }
        if (!record.commitSha().equals(requested.commitSha())) {
            return ApprovalValidationResult.of(ApprovalValidationReasonCode.COMMIT_SHA_MISMATCH, record);
        }
        if (!record.environment().equals(requested.environment())) {
            return ApprovalValidationResult.of(ApprovalValidationReasonCode.ENVIRONMENT_MISMATCH, record);
        }
        if (!record.planSha256().equals(requested.planSha256())) {
            return ApprovalValidationResult.of(ApprovalValidationReasonCode.PLAN_HASH_MISMATCH, record);
        }

        ApprovalStatus effective = record.effectiveStatus(now);
        return switch (effective) {
            case REVOKED -> ApprovalValidationResult.of(ApprovalValidationReasonCode.APPROVAL_REVOKED, record);
            case SUPERSEDED -> ApprovalValidationResult.of(ApprovalValidationReasonCode.APPROVAL_SUPERSEDED, record);
            case EXPIRED -> ApprovalValidationResult.of(ApprovalValidationReasonCode.APPROVAL_EXPIRED, record);
            case ACTIVE -> ApprovalValidationResult.of(ApprovalValidationReasonCode.VALID, record);
        };
    }
}
