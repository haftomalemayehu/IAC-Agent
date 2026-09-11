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

    /**
     * Atomically creates {@code newRecord} and, in the SAME unit of work, attempts to transition
     * {@code priorApprovalId} from ACTIVE to SUPERSEDED referencing it. Either both effects become
     * visible to every other caller together, or neither does - this is what makes
     * {@link ApprovalRecordProducer#issueSuperseding} safe against partial failure (a crash, a
     * dropped connection, a constraint violation, or - for an in-heap implementation - a
     * concurrent reader) between the two operations.
     *
     * <p><b>There is deliberately no default implementation.</b> "Insert the new record, then
     * separately call {@link #supersede}" as two independently successful calls does NOT satisfy
     * this contract: a failure, or merely a concurrent observer, between the two steps could see
     * or leave the new record present with the prior one still ACTIVE, or the prior one already
     * SUPERSEDED while the new record does not yet exist. A default implementation built from
     * {@link #create} and {@link #supersede} would let a future repository implementation compile
     * successfully while silently failing to provide this atomicity guarantee - exactly the kind
     * of contract erosion this method exists to prevent. Every implementation, including
     * {@link InMemoryApprovalRepository}, must provide its own atomic implementation appropriate
     * to its backend (a database transaction for a relational store; a single critical section
     * covering both the insert and the transition, held for the duration of both, for an in-heap
     * store - not two independently-locked operations).
     *
     * <p>The prior approval's transition outcome (SUCCESS if it was ACTIVE and is now superseded,
     * or ALREADY_TRANSITIONED if it was already inactive, or NOT_FOUND if it does not exist) does
     * not prevent {@code newRecord} from being created - matching the existing, accepted
     * issueSuperseding semantics: a prior approval that was already revoked or superseded by
     * something else is not itself an error for issuing a fresh approval.
     */
    SupersedingIssuanceResult createAndSupersede(ApprovalRecord newRecord, String priorApprovalId, Instant supersededAt);
}
