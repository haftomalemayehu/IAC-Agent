package com.iacagent.iacagent.runner;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * A process-local, non-durable {@link RunnerLedgerRepository}, for domain-level unit tests only -
 * exactly the same role {@code InMemoryApprovalRepository} plays for the approval subsystem. All
 * restart-durability requirements are proven against {@code JdbcRunnerLedgerRepository}, never
 * this class. A single lock guards every operation for its full duration, giving the same
 * genuine (not merely probable) atomicity guarantee a real transactional backend provides.
 */
public final class InMemoryRunnerLedgerRepository implements RunnerLedgerRepository {

    private final Object lock = new Object();
    private final Map<String, Row> rows = new HashMap<>();

    private record Row(String fingerprint, RunnerClaimState claimState, RunnerEvidence evidence) {
    }

    @Override
    public RunnerClaimOutcome claim(RunnerRequest request, Instant claimedAt) {
        synchronized (lock) {
            String fingerprint = request.fingerprintSha256();
            Row existing = rows.get(request.runnerRequestId());
            if (existing == null) {
                rows.put(request.runnerRequestId(), new Row(fingerprint, RunnerClaimState.CLAIMED, null));
                return RunnerClaimOutcome.CLAIMED;
            }
            if (!existing.fingerprint().equals(fingerprint)) {
                return RunnerClaimOutcome.FINGERPRINT_MISMATCH;
            }
            return existing.claimState() == RunnerClaimState.COMPLETED
                    ? RunnerClaimOutcome.DUPLICATE_SAME_FINGERPRINT
                    : RunnerClaimOutcome.INCOMPLETE_PRIOR_CLAIM;
        }
    }

    @Override
    public void recordTerminalEvidence(RunnerEvidence evidence) {
        synchronized (lock) {
            Row existing = rows.get(evidence.runnerRequestId());
            if (existing == null || existing.claimState() == RunnerClaimState.COMPLETED) {
                throw new IllegalStateException(
                        "cannot record terminal evidence for an id that was not freshly claimed: " + evidence.runnerRequestId());
            }
            rows.put(evidence.runnerRequestId(), new Row(existing.fingerprint(), RunnerClaimState.COMPLETED, evidence));
        }
    }

    @Override
    public Optional<RunnerEvidence> findHistoricalEvidence(String runnerRequestId) {
        synchronized (lock) {
            Row row = rows.get(runnerRequestId);
            return row != null && row.claimState() == RunnerClaimState.COMPLETED ? Optional.of(row.evidence()) : Optional.empty();
        }
    }
}
