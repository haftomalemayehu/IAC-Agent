package com.iacagent.iacagent.approval;

/**
 * Independently supplied, reviewed evidence describing *what* change is being approved. This is
 * one of two inputs to {@link ApprovalRecordProducer#issue} - the other, {@link TrustedApprovalContext},
 * supplies *who* is approving it. Deliberately excludes {@code approvedBy}, {@code approvedAt},
 * and {@code expiresAt}: approver identity must come only from a {@link TrustedApprovalContext},
 * and timestamps must come only from the producer's injected {@link java.time.Clock} and
 * {@link ApprovalTtlPolicy} - never from this request, so this type's shape does not itself
 * suggest to a future caller that they may supply an arbitrary approver name or historical
 * timestamp.
 *
 * <p>This type is never populated from unstructured LLM output; see
 * docs/phase-2a-threat-model.md SS2 threat 24/25.
 */
public record ApprovalIssuanceRequest(
        String repository,
        String commitSha,
        String environment,
        String planSha256,
        ApprovalProvenance provenance
) {
    public ApprovalIssuanceRequest {
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
        if (provenance == null) {
            provenance = ApprovalProvenance.NONE;
        }
    }
}
