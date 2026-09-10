package com.iacagent.iacagent.approval;

import java.time.Instant;
import java.util.Optional;

/**
 * The authoritative store of ApprovalRecords. This is the only component permitted to persist or
 * transition approval state; {@link ApprovalProvider} only ever reads from it.
 *
 * <p>Implementations MUST make {@link #revoke} and {@link #supersede} genuine atomic
 * compare-and-set operations against the persisted status - never a separate read followed by a
 * separate write - so that when two callers race to transition the same approvalId, exactly one
 * receives {@link TransitionOutcome#SUCCESS} and every other caller receives
 * {@link TransitionOutcome#ALREADY_TRANSITIONED}, with no window in which both could succeed.
 */
public interface ApprovalRepository {

    /** Persists a freshly issued, ACTIVE approval. Fails if approvalId already exists. */
    ApprovalRecord create(ApprovalRecord record);

    /** Never returns a default/empty record for a missing id - absence is Optional.empty(). */
    Optional<ApprovalRecord> find(String approvalId);

    /** Atomic ACTIVE -&gt; REVOKED transition. */
    TransitionOutcome revoke(String approvalId, Instant revokedAt, String revokedBy, String reason);

    /** Atomic ACTIVE -&gt; SUPERSEDED transition, linking to the record and plan that replaced it. */
    TransitionOutcome supersede(String approvalId, Instant supersededAt, String supersedingApprovalId, String supersedingPlanSha256);
}
