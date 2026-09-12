package com.iacagent.iacagent.runner;

import java.util.List;
import java.util.Set;

/**
 * A closed, trusted-bootstrap-configured policy for which Terraform provider and module sources
 * {@code terraform init} may be allowed to act on. Never constructed from a {@link RunnerRequest}
 * field or from repository content - exactly like {@link TerraformExecutableDescriptor}, this is
 * something trusted code configures {@link ControlledTerraformOperationCoordinator} with, not
 * something a caller can widen or a repository can override by declaring a source the policy does
 * not already allow.
 *
 * <p>Defaults are restrictive: an empty {@code allowedProviderSourcePrefixes}/
 * {@code allowedModuleSourcePrefixes} allows nothing at all. {@link #restrictiveDefault()} is the
 * suggested Phase 2B-4 starting point - only the official HashiCorp provider namespace, no git
 * modules, no local modules, registry network access permitted (since without it, no provider can
 * ever be fetched at all).
 */
public record TerraformSourcePolicy(
        Set<String> allowedProviderSourcePrefixes,
        Set<String> allowedModuleSourcePrefixes,
        boolean allowRegistryNetworkAccess,
        boolean allowGitModuleSources,
        boolean allowLocalModuleSources
) {
    public TerraformSourcePolicy {
        allowedProviderSourcePrefixes = allowedProviderSourcePrefixes == null ? Set.of() : Set.copyOf(allowedProviderSourcePrefixes);
        allowedModuleSourcePrefixes = allowedModuleSourcePrefixes == null ? Set.of() : Set.copyOf(allowedModuleSourcePrefixes);
    }

    /** Restrictive Phase 2B-4 default: only {@code registry.terraform.io/hashicorp/*} providers,
     * no module sources of any kind allowed, registry network access permitted (required for any
     * provider source to ever be usable at all). */
    public static TerraformSourcePolicy restrictiveDefault() {
        return new TerraformSourcePolicy(Set.of("registry.terraform.io/hashicorp/"), Set.of(), true, false, false);
    }

    public boolean isProviderSourceAllowed(String source) {
        if (source == null || source.isBlank()) {
            return false;
        }
        return allowedProviderSourcePrefixes.stream().anyMatch(source::startsWith);
    }

    public boolean isModuleSourceAllowed(String source) {
        if (source == null || source.isBlank()) {
            return false;
        }
        if (isLocalModuleSource(source)) {
            return allowLocalModuleSources;
        }
        if (isGitModuleSource(source)) {
            return allowGitModuleSources;
        }
        return allowedModuleSourcePrefixes.stream().anyMatch(source::startsWith);
    }

    private static boolean isLocalModuleSource(String source) {
        return source.startsWith("./") || source.startsWith("../");
    }

    private static boolean isGitModuleSource(String source) {
        return source.startsWith("git::") || source.startsWith("git@") || source.contains("github.com") || source.endsWith(".git");
    }

    /** Sorted, deduplicated view of the allowed provider prefixes - for evidence/reporting only. */
    public List<String> allowedProviderSourcePrefixesSorted() {
        return allowedProviderSourcePrefixes.stream().sorted().toList();
    }
}
