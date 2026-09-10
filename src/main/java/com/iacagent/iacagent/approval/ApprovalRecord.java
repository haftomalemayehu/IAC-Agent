package com.iacagent.iacagent.approval;

import java.time.Instant;

/**
 * An authoritative, plan-hash-bound approval record, per docs/phase-2a-execution-contract.md SS4.
 *
 * <p>The authorization bindings - repository, commitSha, environment, planSha256, approvedBy,
 * approvedAt - are immutable for the lifetime of a given approvalId. There is no "edit" operation.
 * If any binding needs to change, that is a new ApprovalRecord with a new approvalId (see
 * {@link ApprovalRecordProducer#issueSuperseding}), never a mutation of this one.
 *
 * <p>{@code revokedAt}/{@code revokedBy}/{@code revokedReason} and
 * {@code supersededAt}/{@code supersedingApprovalId}/{@code supersedingPlanSha256} are the only
 * fields that ever change after creation, and only via the one-way ACTIVE -&gt; REVOKED or
 * ACTIVE -&gt; SUPERSEDED transitions performed by {@link ApprovalRepository}. This class itself
 * has no mutating methods; a transition produces a new record instance via
 * {@link #withRevocation} / {@link #withSupersession}, it never mutates the fields of an existing
 * instance in place.
 */
public record ApprovalRecord(
        String approvalId,
        String repository,
        String commitSha,
        String environment,
        String planSha256,
        String approvedBy,
        Instant approvedAt,
        Instant expiresAt,
        ApprovalStatus status,
        ApprovalProvenance provenance,
        Instant revokedAt,
        String revokedBy,
        String revokedReason,
        Instant supersededAt,
        String supersedingApprovalId,
        String supersedingPlanSha256
) {
    public ApprovalRecord {
        if (approvalId == null || approvalId.isBlank()) {
            throw new IllegalArgumentException("approvalId is required");
        }
        if (repository == null || repository.isBlank()) {
            throw new IllegalArgumentException("repository is required");
        }
        if (commitSha == null || commitSha.isBlank()) {
            throw new IllegalArgumentException("commitSha is required");
        }
        if (environment == null || environment.isBlank()) {
            throw new IllegalArgumentException("environment is required");
        }
        if (planSha256 == null || planSha256.isBlank()) {
            throw new IllegalArgumentException("planSha256 is required");
        }
        if (approvedBy == null || approvedBy.isBlank()) {
            throw new IllegalArgumentException("approvedBy is required");
        }
        if (approvedAt == null) {
            throw new IllegalArgumentException("approvedAt is required");
        }
        if (expiresAt == null) {
            throw new IllegalArgumentException("expiresAt is required");
        }
        if (!expiresAt.isAfter(approvedAt)) {
            throw new IllegalArgumentException("expiresAt must be after approvedAt");
        }
        if (status == null) {
            throw new IllegalArgumentException("status is required");
        }
        if (status == ApprovalStatus.EXPIRED) {
            throw new IllegalArgumentException(
                    "EXPIRED is a computed effective status, never a persisted one - see ApprovalStatus");
        }
        if (provenance == null) {
            provenance = ApprovalProvenance.NONE;
        }
    }

    /** The identity this approval authorizes - matched against an execution request's identity. */
    public ExecutionIdentity identity() {
        return new ExecutionIdentity(repository, commitSha, environment, planSha256);
    }

    /**
     * The status that actually governs whether this approval may be used right now: the
     * persisted status, unless it is still ACTIVE but has timed out, in which case EXPIRED.
     * Callers MUST use this, not the raw {@link #status()} field, to decide validity.
     */
    public ApprovalStatus effectiveStatus(Instant now) {
        if (status == ApprovalStatus.ACTIVE && !now.isBefore(expiresAt)) {
            return ApprovalStatus.EXPIRED;
        }
        return status;
    }

    public ApprovalRecord withRevocation(Instant revokedAt, String revokedBy, String revokedReason) {
        return new ApprovalRecord(
                approvalId, repository, commitSha, environment, planSha256,
                approvedBy, approvedAt, expiresAt, ApprovalStatus.REVOKED, provenance,
                revokedAt, revokedBy, revokedReason,
                supersededAt, supersedingApprovalId, supersedingPlanSha256
        );
    }

    public ApprovalRecord withSupersession(Instant supersededAt, String supersedingApprovalId, String supersedingPlanSha256) {
        return new ApprovalRecord(
                approvalId, repository, commitSha, environment, planSha256,
                approvedBy, approvedAt, expiresAt, ApprovalStatus.SUPERSEDED, provenance,
                revokedAt, revokedBy, revokedReason,
                supersededAt, supersedingApprovalId, supersedingPlanSha256
        );
    }
}
