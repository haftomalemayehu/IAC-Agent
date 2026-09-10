package com.iacagent.iacagent.approval;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The Phase 2C-1 "minimal authoritative producer" storage backend: an in-process, thread-safe,
 * NON-DURABLE store. All approval records are lost on process restart.
 *
 * <p><b>HARD GATE - not a note to revisit eventually:</b> this implementation is acceptable only
 * because, at Phase 2C-1, there is still zero execution consumer of approval records. It MUST be
 * replaced by durable, authoritative storage (a real database, or whatever backing store Phase
 * 2C's production approval workflow settles on) before Phase 2A runtime execution is enabled.
 * An executor that can authorize {@code terraform apply} against an approval record that a
 * process restart could silently have discarded is not an acceptable design - this class must
 * never be reachable from that code path. Whoever wires up the Phase 2A executor's
 * {@link ApprovalProvider} dependency must not default to this class.
 *
 * <p>What this class does guarantee, regardless of that durability gap: the atomicity contract
 * required by {@link ApprovalRepository}. Each approvalId's status transitions via a genuine
 * compare-and-set on an {@link AtomicReference}, so a read-then-write race between two concurrent
 * transition attempts is structurally impossible. That guarantee is independent of the storage
 * backend and must be preserved by whatever durable implementation eventually replaces this one.
 */
public final class InMemoryApprovalRepository implements ApprovalRepository {

    private final ConcurrentHashMap<String, AtomicReference<ApprovalRecord>> records = new ConcurrentHashMap<>();

    @Override
    public ApprovalRecord create(ApprovalRecord record) {
        AtomicReference<ApprovalRecord> ref = new AtomicReference<>(record);
        AtomicReference<ApprovalRecord> existing = records.putIfAbsent(record.approvalId(), ref);
        if (existing != null) {
            throw new IllegalStateException("approvalId already exists: " + record.approvalId());
        }
        return record;
    }

    @Override
    public Optional<ApprovalRecord> find(String approvalId) {
        AtomicReference<ApprovalRecord> ref = records.get(approvalId);
        return ref == null ? Optional.empty() : Optional.of(ref.get());
    }

    @Override
    public TransitionOutcome revoke(String approvalId, Instant revokedAt, String revokedBy, String reason) {
        return transition(approvalId, current -> current.withRevocation(revokedAt, revokedBy, reason));
    }

    @Override
    public TransitionOutcome supersede(String approvalId, Instant supersededAt, String supersedingApprovalId, String supersedingPlanSha256) {
        return transition(approvalId, current -> current.withSupersession(supersededAt, supersedingApprovalId, supersedingPlanSha256));
    }

    /**
     * Retries the compare-and-set until either it succeeds against the current ACTIVE record, or
     * a fresh read shows the record is no longer ACTIVE - at which point this call has lost the
     * race (or the record was never ACTIVE) and returns ALREADY_TRANSITIONED without writing
     * anything. This is the mechanism that guarantees exactly one of two concurrent callers wins.
     */
    private TransitionOutcome transition(String approvalId, java.util.function.Function<ApprovalRecord, ApprovalRecord> transitionFn) {
        AtomicReference<ApprovalRecord> ref = records.get(approvalId);
        if (ref == null) {
            return TransitionOutcome.NOT_FOUND;
        }
        while (true) {
            ApprovalRecord current = ref.get();
            if (current.status() != ApprovalStatus.ACTIVE) {
                return TransitionOutcome.ALREADY_TRANSITIONED;
            }
            ApprovalRecord updated = transitionFn.apply(current);
            if (ref.compareAndSet(current, updated)) {
                return TransitionOutcome.SUCCESS;
            }
            // Another thread updated the record between our read and our CAS attempt.
            // Loop and re-evaluate against the fresh value rather than blindly retrying the write.
        }
    }
}
