package com.iacagent.iacagent.identity;

/**
 * One trusted, control-plane-configured rule: "a workflow at {@code workflowRef}, in a repository
 * owned by {@code repositoryOwner}, may federate credentials for {@code repository} when the
 * EXECUTION REQUEST declares {@code environment}." Never derived from a request, a token, or
 * repository content - configured once, by whoever operates this control plane.
 *
 * <p>{@code environment} here is the environment the EXECUTION REQUEST is permitted to declare, not
 * necessarily a GitHub "Environments" feature claim - a workflow that never uses GitHub Environments
 * carries no {@code environment} claim at all, and that is fine; this rule still scopes which
 * request-declared environments it may act for. See {@link TrustedWorkloadAuthorizationPolicy}.
 */
public record AllowedWorkload(String repository, String repositoryOwner, String environment, String workflowRef) {
    public AllowedWorkload {
        require(repository, "repository");
        require(repositoryOwner, "repositoryOwner");
        require(environment, "environment");
        require(workflowRef, "workflowRef");
    }

    private static void require(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
    }
}
