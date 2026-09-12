package com.iacagent.iacagent.runner;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The keyed form a single file's source extraction produces - {@code providerSourcesByLocalName}
 * (the {@code required_providers} local name, e.g. {@code "aws"}) and
 * {@code moduleSourcesByLabel} (the module block's own label, e.g. {@code "foo"} for
 * {@code module "foo" { ... }}). {@link TerraformConfigSourceExtractor} merges these maps ACROSS
 * files with override-file precedence (a later map's entry for the same key replaces an earlier
 * one) - this is only possible because the key is preserved here, unlike a flat list of resolved
 * source strings, which would have no notion of "these two entries are for the same
 * provider/module" once the file they each came from stopped mattering.
 *
 * <p>{@code impliedProviderLocalNames} carries provider local names this file's {@code resource}/
 * {@code data}/{@code provider} blocks reference WITHOUT necessarily declaring a
 * {@code required_providers} entry for - accumulated as a UNION across files (an override file does
 * not "un-imply" a provider a regular file's resource block already implied), unlike the
 * provider/module maps' replace-by-key semantics.
 */
record TerraformKeyedConfigSources(Map<String, String> providerSourcesByLocalName, Map<String, String> moduleSourcesByLabel,
                                    Set<String> impliedProviderLocalNames) {

    TerraformKeyedConfigSources {
        providerSourcesByLocalName = providerSourcesByLocalName == null ? Map.of() : Map.copyOf(providerSourcesByLocalName);
        moduleSourcesByLabel = moduleSourcesByLabel == null ? Map.of() : Map.copyOf(moduleSourcesByLabel);
        impliedProviderLocalNames = impliedProviderLocalNames == null ? Set.of() : Set.copyOf(impliedProviderLocalNames);
    }

    static TerraformKeyedConfigSources empty() {
        return new TerraformKeyedConfigSources(Map.of(), Map.of(), Set.of());
    }

    TerraformConfigSourceManifest toManifest() {
        return new TerraformConfigSourceManifest(
                List.copyOf(providerSourcesByLocalName.values()),
                List.copyOf(moduleSourcesByLabel.values()),
                providerSourcesByLocalName.keySet(),
                impliedProviderLocalNames);
    }

    /** Layers {@code overrides} on top of {@code this}: an entry in {@code overrides} for a key
     * already present here REPLACES this one's value for that key, exactly as a Terraform override
     * file's redeclaration of the same provider/module supersedes the original.
     * {@code impliedProviderLocalNames} is unioned, never replaced - a resource block's implied
     * provider requirement in one file is not erased by an override file processed afterward. */
    TerraformKeyedConfigSources layeredWith(TerraformKeyedConfigSources overrides) {
        Map<String, String> providers = new LinkedHashMap<>(providerSourcesByLocalName);
        providers.putAll(overrides.providerSourcesByLocalName());
        Map<String, String> modules = new LinkedHashMap<>(moduleSourcesByLabel);
        modules.putAll(overrides.moduleSourcesByLabel());
        Set<String> implied = new LinkedHashSet<>(impliedProviderLocalNames);
        implied.addAll(overrides.impliedProviderLocalNames());
        return new TerraformKeyedConfigSources(providers, modules, implied);
    }
}
