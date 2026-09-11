package com.iacagent.iacagent.runner;

import java.time.Instant;
import java.util.Optional;

/**
 * The authoritative source of runner-request-consumption and historical-evidence truth. This is
 * what makes duplicate/replay detection durable across process restart, replacing Phase 2B-1's
 * process-local maps inside {@link ControlledRunner} - per the architecture discipline this
 * package follows, {@code ControlledRunner} orchestrates this repository but must never
 * manufacture consumption/evidence truth itself.
 *
 * <p>No general update API is exposed. Only three narrow operations exist: claim a previously
 * unseen id, record the one-and-only terminal outcome for a claimed id, and read back historical
 * evidence for audit. There is no method that could rewrite an already-COMPLETED row's outcome.
 */
public interface RunnerLedgerRepository {

    /**
     * Atomically attempts to claim {@code request.runnerRequestId()}. Exactly one caller may ever
     * receive {@link RunnerClaimOutcome#CLAIMED} for a given id - concurrent callers racing on the
     * same previously-unseen id must see exactly one CLAIMED and the rest
     * {@link RunnerClaimOutcome#INCOMPLETE_PRIOR_CLAIM} (or a fingerprint-based outcome, if their
     * request differs). Must survive process restart: a claim made before a restart remains
     * authoritative after it.
     */
    RunnerClaimOutcome claim(RunnerRequest request, Instant claimedAt);

    /**
     * Records the one-and-only terminal outcome for a request this caller successfully claimed,
     * transitioning it from {@link RunnerClaimState#CLAIMED} to {@link RunnerClaimState#COMPLETED}.
     * Must throw (an implementation-specific unchecked exception, never silently no-op) if the id
     * was not in the CLAIMED state - that indicates a calling-discipline violation (recording
     * evidence for an id this caller never claimed, or recording it twice), not a normal outcome.
     */
    void recordTerminalEvidence(RunnerEvidence evidence);

    /**
     * The original, immutable evidence for a COMPLETED request, for audit only. Returns
     * {@link Optional#empty()} for an unknown id AND for an id that is still only CLAIMED (has no
     * terminal evidence yet) - both are "nothing to report," never a default/placeholder evidence.
     * This is never re-validated and never implies current authorization - see
     * {@link ControlledRunner#execute}.
     */
    Optional<RunnerEvidence> findHistoricalEvidence(String runnerRequestId);
}
