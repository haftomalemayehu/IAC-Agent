package com.iacagent.iacagent.approval;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

/**
 * The Phase 2C-1 "minimal authoritative producer" storage backend: an in-process, thread-safe,
 * NON-DURABLE store. All approval records are lost on process restart.
 *
 * <p><b>HARD GATE - not a note to revisit eventually:</b> this implementation is acceptable only
 * because, at Phase 2C-1/2C-2, there is still zero execution consumer of approval records. It MUST
 * be replaced by durable, authoritative storage before Phase 2A runtime execution is enabled. An
 * executor that can authorize {@code terraform apply} against an approval record that a process
 * restart could silently have discarded is not an acceptable design - this class must never be
 * reachable from that code path. Whoever wires up the Phase 2A executor's {@link ApprovalProvider}
 * dependency must not default to this class. See {@code com.iacagent.iacagent.approval.jdbc.JdbcApprovalRepository}
 * for the durable reference/acceptance backend, itself gated for production execution use behind a
 * real PostgreSQL integration/concurrency verification pass - see that class's javadoc.
 *
 * <p>What this class does guarantee, regardless of that durability gap: the full atomicity
 * contract required by {@link ApprovalRepository}, including {@link #createAndSupersede}. Every
 * public method acquires a single lock for its entire duration, so no concurrent caller can ever
 * observe, or cause, a half-completed composite operation - e.g. a new record present while the
 * prior one it is meant to supersede is still ACTIVE, or a prior record already SUPERSEDED while
 * the new record referenced by it does not yet exist. This is a coarser guarantee than
 * {@code JdbcApprovalRepository}'s row-level transaction (every operation here serializes against
 * every other, not just the two rows a given operation touches), which is an acceptable and
 * deliberate simplification for an in-heap reference/test double whose purpose is correctness and
 * determinism, not throughput.
 */
public final class InMemoryApprovalRepository implements ApprovalRepository {

    private final Object lock = new Object();
    private final Map<String, ApprovalRecord> records = new HashMap<>();

    @Override
    public ApprovalRecord create(ApprovalRecord record) {
        synchronized (lock) {
            insertLocked(record);
            return record;
        }
    }

    @Override
    public Optional<ApprovalRecord> find(String approvalId) {
        synchronized (lock) {
            return Optional.ofNullable(records.get(approvalId));
        }
    }

    @Override
    public TransitionOutcome revoke(String approvalId, Instant revokedAt, String revokedBy, String reason) {
        synchronized (lock) {
            return transitionLocked(approvalId, current -> current.withRevocation(revokedAt, revokedBy, reason));
        }
    }

    @Override
    public TransitionOutcome supersede(String approvalId, Instant supersededAt, String supersedingApprovalId, String supersedingPlanSha256) {
        synchronized (lock) {
            return transitionLocked(approvalId, current -> current.withSupersession(supersededAt, supersedingApprovalId, supersedingPlanSha256));
        }
    }

    /**
     * All-or-nothing: on any outcome other than SUCCESS, {@code newRecord} must not exist
     * afterward and the prior approval must be unchanged. Every failure condition (duplicate new
     * id, missing prior, prior not ACTIVE) is checked, and the resulting superseded prior record
     * is fully constructed, BEFORE either map mutation happens - so there is nothing left that can
     * fail once the first {@code put} runs, and no rollback is needed. An earlier revision
     * inserted the new record unconditionally and only then attempted the prior's transition,
     * which left a standalone ACTIVE "new" approval behind whenever the prior transition failed -
     * exactly the half-state this method exists to make impossible.
     */
    @Override
    public SupersedingIssuanceResult createAndSupersede(ApprovalRecord newRecord, String priorApprovalId, Instant supersededAt) {
        synchronized (lock) {
            if (records.containsKey(newRecord.approvalId())) {
                throw new IllegalStateException("approvalId already exists: " + newRecord.approvalId());
            }
            ApprovalRecord prior = records.get(priorApprovalId);
            if (prior == null) {
                return new SupersedingIssuanceResult(null, TransitionOutcome.NOT_FOUND);
            }
            if (prior.status() != ApprovalStatus.ACTIVE) {
                return new SupersedingIssuanceResult(null, TransitionOutcome.ALREADY_TRANSITIONED);
            }

            ApprovalRecord supersededPrior = prior.withSupersession(supersededAt, newRecord.approvalId(), newRecord.planSha256());

            // Every failure condition has already been checked above - both writes below are now
            // guaranteed to succeed, and both happen before releasing the lock, so no concurrent
            // caller can ever observe just one of them.
            records.put(newRecord.approvalId(), newRecord);
            records.put(priorApprovalId, supersededPrior);
            return new SupersedingIssuanceResult(newRecord.approvalId(), TransitionOutcome.SUCCESS);
        }
    }

    /** Caller must hold {@link #lock}. */
    private void insertLocked(ApprovalRecord record) {
        if (records.containsKey(record.approvalId())) {
            throw new IllegalStateException("approvalId already exists: " + record.approvalId());
        }
        records.put(record.approvalId(), record);
    }

    /** Caller must hold {@link #lock}. */
    private TransitionOutcome transitionLocked(String approvalId, Function<ApprovalRecord, ApprovalRecord> transitionFn) {
        ApprovalRecord current = records.get(approvalId);
        if (current == null) {
            return TransitionOutcome.NOT_FOUND;
        }
        if (current.status() != ApprovalStatus.ACTIVE) {
            return TransitionOutcome.ALREADY_TRANSITIONED;
        }
        records.put(approvalId, transitionFn.apply(current));
        return TransitionOutcome.SUCCESS;
    }
}
