package com.iacagent.iacagent.approval;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * The Phase 2C-1 "minimal authoritative approval-record producer" - the only implementation of
 * {@link ApprovalAuthority}. Constructs ApprovalRecords from independently supplied change
 * metadata ({@link ApprovalIssuanceRequest}) and an authenticated approver identity
 * ({@link TrustedApprovalContext}), and persists them via {@link ApprovalRepository}.
 *
 * <p>Every timestamp this class writes ({@code approvedAt}, {@code revokedAt},
 * {@code supersededAt}) comes from the injected {@link Clock}, never from a caller-supplied
 * value - this is the single time authority in the system. {@code expiresAt} is derived from
 * the injected {@link ApprovalTtlPolicy}, not accepted as a parameter.
 *
 * <p>Deliberately not implemented here: any notion of accepting a caller-supplied "approved=true"
 * flag, an arbitrary {@code approvedBy} string, or any free-form text, as authority. The only
 * thing that grants approval authority is a caller possessing a genuine
 * {@link TrustedApprovalContext} - which in Phase 2C-1 is the acceptance test / fixture caller
 * standing in for a human approver, and in Phase 2C proper will be constructed only by the
 * authoritative human-approval workflow (GitHub Environment protection / HCP Terraform approval
 * gate).
 *
 * <p>Issuance returns only the {@code approvalId} string - consumers that need to reference an
 * approval never receive, and therefore can never redistribute, the mutable approval fields
 * themselves.
 */
public final class ApprovalRecordProducer implements ApprovalAuthority {

    private final ApprovalRepository repository;
    private final Clock clock;
    private final ApprovalTtlPolicy ttlPolicy;
    private final Supplier<String> approvalIdGenerator;

    public ApprovalRecordProducer(ApprovalRepository repository, Clock clock, ApprovalTtlPolicy ttlPolicy) {
        this(repository, clock, ttlPolicy, () -> "approval-" + UUID.randomUUID());
    }

    /** Package-visible for deterministic tests that need to control generated ids. */
    ApprovalRecordProducer(ApprovalRepository repository, Clock clock, ApprovalTtlPolicy ttlPolicy, Supplier<String> approvalIdGenerator) {
        if (repository == null) {
            throw new IllegalArgumentException("repository is required");
        }
        if (clock == null) {
            throw new IllegalArgumentException("clock is required");
        }
        if (ttlPolicy == null) {
            throw new IllegalArgumentException("ttlPolicy is required");
        }
        if (approvalIdGenerator == null) {
            throw new IllegalArgumentException("approvalIdGenerator is required");
        }
        this.repository = repository;
        this.clock = clock;
        this.ttlPolicy = ttlPolicy;
        this.approvalIdGenerator = approvalIdGenerator;
    }

    @Override
    public String issue(ApprovalIssuanceRequest request, TrustedApprovalContext context) {
        ApprovalRecord record = buildRecord(request, context);
        repository.create(record);
        return record.approvalId();
    }

    private ApprovalRecord buildRecord(ApprovalIssuanceRequest request, TrustedApprovalContext context) {
        if (request == null) {
            throw new IllegalArgumentException("request is required");
        }
        if (context == null) {
            throw new IllegalArgumentException("context is required");
        }

        Instant approvedAt = clock.instant();
        Instant expiresAt = approvedAt.plus(ttlPolicy.ttlFor(request.environment()));
        String approvalId = approvalIdGenerator.get();
        return new ApprovalRecord(
                approvalId,
                request.repository(),
                request.commitSha(),
                request.environment(),
                request.planSha256(),
                context.principalId(),
                approvedAt,
                expiresAt,
                ApprovalStatus.ACTIVE,
                request.provenance(),
                null, null, null,
                null, null, null
        );
    }

    @Override
    public TransitionOutcome revoke(String approvalId, TrustedApprovalContext context, String reason) {
        if (approvalId == null || approvalId.isBlank()) {
            throw new IllegalArgumentException("approvalId is required");
        }
        if (context == null) {
            throw new IllegalArgumentException("context is required");
        }
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("reason is required");
        }
        return repository.revoke(approvalId, clock.instant(), context.principalId(), reason);
    }

    @Override
    public SupersedingIssuanceResult issueSuperseding(ApprovalIssuanceRequest newRequest, TrustedApprovalContext context, String priorApprovalId) {
        if (newRequest == null) {
            throw new IllegalArgumentException("newRequest is required");
        }
        if (context == null) {
            throw new IllegalArgumentException("context is required");
        }
        if (priorApprovalId == null || priorApprovalId.isBlank()) {
            throw new IllegalArgumentException("priorApprovalId is required");
        }

        // Read-only sanity check, not part of the atomic write below: guards against obviously
        // wrong usage (naming a prior approval for an unrelated repository/environment). This is
        // deliberately a plain read against whatever state is visible right now - it is not
        // itself required to be transactionally consistent with the write that follows, unlike
        // the insert+supersede pair, which repository.createAndSupersede protects atomically.
        Optional<ApprovalRecord> prior = repository.find(priorApprovalId);
        if (prior.isEmpty()) {
            throw new IllegalArgumentException("no approval found for priorApprovalId: " + priorApprovalId);
        }
        ApprovalRecord priorRecord = prior.get();
        if (!priorRecord.repository().equals(newRequest.repository()) || !priorRecord.environment().equals(newRequest.environment())) {
            throw new IllegalArgumentException(
                    "priorApprovalId does not share repository/environment with newRequest - refusing to supersede across unrelated contexts");
        }

        ApprovalRecord newRecord = buildRecord(newRequest, context);
        return repository.createAndSupersede(newRecord, priorApprovalId, clock.instant());
    }
}
