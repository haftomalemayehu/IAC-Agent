package com.iacagent.iacagent.runner;

/**
 * The durable, persisted lifecycle of one {@code runnerRequestId} in {@link RunnerLedgerRepository}.
 * CLAIMED means an attempt owns this id but has not yet recorded a terminal outcome - this is the
 * state a crashed process leaves behind, and the state two genuinely concurrent callers might both
 * observe for a brief moment (though only one of them ever performed the atomic claim itself).
 * COMPLETED means {@link RunnerLedgerRepository#recordTerminalEvidence} has run and the row's
 * evidence fields are authoritative. There is no third state: this is intentionally a two-state
 * machine layered underneath {@link RunnerState}'s richer, in-memory-only pipeline states.
 */
public enum RunnerClaimState {
    CLAIMED,
    COMPLETED
}
