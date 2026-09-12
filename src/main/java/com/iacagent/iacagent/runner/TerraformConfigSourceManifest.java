package com.iacagent.iacagent.runner;

import java.util.List;
import java.util.Set;

/**
 * The canonical, deterministically-extracted set of provider and module sources a staged
 * configuration declares - the output of {@link TerraformConfigSourceExtractor}, checked against
 * {@link TerraformSourcePolicy} before {@code terraform init} is ever launched. Unlike the retired
 * heuristic scanner it replaces, every entry here was extracted by a real parser
 * ({@link TerraformNativeSourceExtractor} for {@code *.tf}, {@link TerraformJsonSourceExtractor}
 * for {@code *.tf.json}) that fails closed ({@link TerraformConfigSourceExtractionException}) rather
 * than silently omitting a source it could not deterministically understand - so an empty list here
 * is a genuine claim ("this configuration declares no provider/module sources"), not "the scanner
 * gave up."
 *
 * <p>{@code declaredProviderLocalNames}/{@code impliedProviderLocalNames} exist to close a gap
 * {@code providerSources} alone cannot: a {@code required_providers} entry is EXPLICIT trust
 * ("this configuration deliberately named this source"), but Terraform can also resolve a provider
 * IMPLICITLY - from a {@code resource}/{@code data} block's type prefix, or a bare
 * {@code provider "x" {}} configuration block - with no {@code required_providers} entry at all,
 * falling back to {@code registry.terraform.io/hashicorp/<local-name>}. {@link TerraformSourcePolicy}
 * can only ever evaluate sources it is actually given; a provider {@code init} might resolve without
 * ever appearing in {@code providerSources} is a policy-enforcement gap, not a supply-chain nuance
 * left to Gate E. {@link ControlledTerraformOperationCoordinator#executeInit} blocks with
 * {@link RunnerReasonCode#TERRAFORM_PROVIDER_REQUIREMENT_IMPLICIT} whenever
 * {@code impliedProviderLocalNames} contains a name absent from {@code declaredProviderLocalNames}.
 *
 * <p>{@code moduleSources} is still populated (parsed and canonicalized) even though Phase 2B-4
 * never lets a non-empty {@code moduleSources} reach {@code init} - see
 * {@link RunnerReasonCode#TERRAFORM_MODULE_DEPENDENCY_GRAPH_UNRESOLVED}.
 */
record TerraformConfigSourceManifest(
        List<String> providerSources,
        List<String> moduleSources,
        Set<String> declaredProviderLocalNames,
        Set<String> impliedProviderLocalNames
) {
    TerraformConfigSourceManifest {
        providerSources = providerSources == null ? List.of() : List.copyOf(providerSources);
        moduleSources = moduleSources == null ? List.of() : List.copyOf(moduleSources);
        declaredProviderLocalNames = declaredProviderLocalNames == null ? Set.of() : Set.copyOf(declaredProviderLocalNames);
        impliedProviderLocalNames = impliedProviderLocalNames == null ? Set.of() : Set.copyOf(impliedProviderLocalNames);
    }

    /** Provider local names Terraform could resolve during {@code init} that never appeared in an
     * explicit {@code required_providers} entry. Non-empty here always blocks (see
     * {@link RunnerReasonCode#TERRAFORM_PROVIDER_REQUIREMENT_IMPLICIT}). */
    Set<String> undeclaredImpliedProviderLocalNames() {
        return impliedProviderLocalNames.stream()
                .filter(name -> !declaredProviderLocalNames.contains(name))
                .collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new));
    }
}
