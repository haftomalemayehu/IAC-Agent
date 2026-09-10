package com.iacagent.iacagent.approval;

import java.util.Optional;

/**
 * The only implementation of ApprovalProvider in Phase 2C-1: a thin, read-only view over an
 * {@link ApprovalRepository}. Phase 2C will later swap the repository's backing store (GitHub
 * Environments / HCP Terraform-derived, per docs/roadmap-phase-2.md SS5) without this class, or
 * the ApprovalProvider interface, needing to change - that is the whole point of the boundary.
 */
public final class RepositoryBackedApprovalProvider implements ApprovalProvider {

    private final ApprovalRepository repository;

    public RepositoryBackedApprovalProvider(ApprovalRepository repository) {
        if (repository == null) {
            throw new IllegalArgumentException("repository is required");
        }
        this.repository = repository;
    }

    @Override
    public Optional<ApprovalRecord> resolve(String approvalId) {
        if (approvalId == null || approvalId.isBlank()) {
            return Optional.empty();
        }
        return repository.find(approvalId);
    }
}
