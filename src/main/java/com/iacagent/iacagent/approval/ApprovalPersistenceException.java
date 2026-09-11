package com.iacagent.iacagent.approval;

/**
 * Thrown by an {@link ApprovalRepository} implementation when a genuine infrastructure failure
 * (database unavailable, transaction timeout, serialization conflict, constraint violation,
 * connection loss) prevents it from determining the true state of an approval or completing a
 * transition.
 *
 * <p>This is deliberately a distinct, unchecked exception type rather than any encoding via a
 * return value, and it is deliberately never caught and converted into a domain outcome anywhere
 * in this package: an infrastructure failure must never be mistaken for
 * {@link ApprovalValidationReasonCode#APPROVAL_NOT_FOUND} (a legitimate domain fact - this
 * approval id was never issued) or for {@link TransitionOutcome#SUCCESS}/{@code ALREADY_TRANSITIONED}
 * (both legitimate outcomes of a transition that actually ran). "Approval authority unavailable"
 * is a different condition from all of those, and callers - including a future Phase 2A executor -
 * must treat an uncaught exception here as "cannot proceed," never as an implicit BLOCKED-and-move-on.
 */
public class ApprovalPersistenceException extends RuntimeException {
    public ApprovalPersistenceException(String message, Throwable cause) {
        super(message, cause);
    }
}
