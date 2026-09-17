package com.iacagent.iacagent.identity;

import com.iacagent.iacagent.runner.RunnerReasonCode;

import java.util.Set;

/**
 * The reference, deterministic {@link WorkloadAuthorizationPolicy}: a fixed, control-plane-supplied
 * set of {@link AllowedWorkload} rules. Fails closed, in this fixed order, on every mismatch the
 * authorization docs require:
 * <ol>
 *   <li>{@code repository} mismatch between the verified identity and the execution request;
 *   <li>{@code commit} mismatch;
 *   <li>{@code environment} mismatch, IF the token itself carries a GitHub Environment claim (a
 *   token that never uses GitHub's optional Environments feature carries none, and that alone is
 *   never a rejection - see {@link AllowedWorkload});
 *   <li>no {@link AllowedWorkload} rule exists for the (repository, environment) pair at all;
 *   <li>the matching rule's {@code repositoryOwner} does not match the verified identity's;
 *   <li>the matching rule's {@code workflowRef} does not match the verified identity's.
 * </ol>
 */
public final class TrustedWorkloadAuthorizationPolicy implements WorkloadAuthorizationPolicy {

    private final Set<AllowedWorkload> allowedWorkloads;

    public TrustedWorkloadAuthorizationPolicy(Set<AllowedWorkload> allowedWorkloads) {
        this.allowedWorkloads = allowedWorkloads == null ? Set.of() : Set.copyOf(allowedWorkloads);
    }

    @Override
    public WorkloadAuthorizationResult authorize(VerifiedWorkloadIdentity identity, String repository, String commitSha, String environment) {
        if (identity == null || repository == null || commitSha == null || environment == null) {
            throw new IllegalArgumentException("identity, repository, commitSha, and environment are all required");
        }
        if (!identity.repository().equals(repository)) {
            return WorkloadAuthorizationResult.denied(RunnerReasonCode.WORKLOAD_IDENTITY_REPOSITORY_MISMATCH);
        }
        if (!identity.commitSha().equals(commitSha)) {
            return WorkloadAuthorizationResult.denied(RunnerReasonCode.WORKLOAD_IDENTITY_COMMIT_MISMATCH);
        }
        if (identity.environment() != null && !identity.environment().equals(environment)) {
            return WorkloadAuthorizationResult.denied(RunnerReasonCode.WORKLOAD_IDENTITY_ENVIRONMENT_MISMATCH);
        }

        Set<AllowedWorkload> candidates = allowedWorkloads.stream()
                .filter(w -> w.repository().equals(repository) && w.environment().equals(environment))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        if (candidates.isEmpty()) {
            return WorkloadAuthorizationResult.denied(RunnerReasonCode.WORKLOAD_IDENTITY_WORKFLOW_NOT_AUTHORIZED);
        }
        // Existence checks below are order-independent by construction, unlike picking a single
        // "the" rule via findFirst() over a Set (whose iteration order is unspecified) - with more
        // than one rule configured for the same (repository, environment), a single arbitrarily
        // picked rule could wrongly deny a workload that a DIFFERENT configured rule does authorize.
        boolean exactMatch = candidates.stream()
                .anyMatch(w -> w.repositoryOwner().equals(identity.repositoryOwner())
                        && w.workflowRef().equals(identity.workflowRef()));
        if (exactMatch) {
            return WorkloadAuthorizationResult.granted();
        }
        boolean ownerMatchesAnyCandidate = candidates.stream()
                .anyMatch(w -> w.repositoryOwner().equals(identity.repositoryOwner()));
        if (!ownerMatchesAnyCandidate) {
            return WorkloadAuthorizationResult.denied(RunnerReasonCode.WORKLOAD_IDENTITY_OWNER_MISMATCH);
        }
        return WorkloadAuthorizationResult.denied(RunnerReasonCode.WORKLOAD_IDENTITY_WORKFLOW_NOT_AUTHORIZED);
    }
}
