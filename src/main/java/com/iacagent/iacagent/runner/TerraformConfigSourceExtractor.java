package com.iacagent.iacagent.runner;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * The single entry point {@link ControlledTerraformOperationCoordinator} uses to obtain a
 * {@link TerraformConfigSourceManifest} from a staged configuration - dispatches each file to
 * {@link TerraformNativeSourceExtractor} ({@code *.tf}) or {@link TerraformJsonSourceExtractor}
 * ({@code *.tf.json}) by its relative path's suffix, and merges the results.
 *
 * <p>Terraform override files ({@code override.tf}/{@code override.tf.json}, or any file ending in
 * {@code _override.tf}/{@code _override.tf.json}) are processed AFTER every regular file, so an
 * override's declaration for the same provider local name or module label wins - the same
 * precedence Terraform's own merge semantics give override files. This is why filenames must be
 * part of the identity binding ({@link TerraformConfigIdentity}) as well as this extraction: the
 * SAME two files with contents swapped between {@code main.tf} and {@code override.tf} can produce
 * a genuinely different manifest.
 *
 * <p>Any file with an unrecognized suffix (not {@code .tf} or {@code .tf.json}) is rejected outright
 * - this runner only ever stages files it itself knows how to interpret for policy purposes, so an
 * unrecognized file extension is never silently skipped.
 */
final class TerraformConfigSourceExtractor {

    private TerraformConfigSourceExtractor() {
    }

    static TerraformConfigSourceManifest extract(List<TerraformConfigIdentity.NamedConfigFile> files) {
        List<TerraformConfigIdentity.NamedConfigFile> regular = new ArrayList<>();
        List<TerraformConfigIdentity.NamedConfigFile> overrides = new ArrayList<>();
        for (TerraformConfigIdentity.NamedConfigFile file : files) {
            String name = file.relativePath();
            if (!name.endsWith(".tf") && !name.endsWith(".tf.json")) {
                throw new TerraformConfigSourceExtractionException("unrecognized configuration file extension: " + name);
            }
            if (isOverrideFile(name)) {
                overrides.add(file);
            } else {
                regular.add(file);
            }
        }
        regular.sort(Comparator.comparing(TerraformConfigIdentity.NamedConfigFile::relativePath));
        overrides.sort(Comparator.comparing(TerraformConfigIdentity.NamedConfigFile::relativePath));

        TerraformKeyedConfigSources combined = TerraformKeyedConfigSources.empty();
        for (TerraformConfigIdentity.NamedConfigFile file : regular) {
            combined = combined.layeredWith(extractOne(file));
        }
        // Override files are layered LAST, in their own relative-path order, so a later override's
        // redeclaration for the same provider local name/module label always wins - exactly
        // Terraform's own override-file merge precedence, and why filenames (not just byte
        // multisets) must distinguish TerraformConfigIdentity's binding (see that class's javadoc).
        for (TerraformConfigIdentity.NamedConfigFile file : overrides) {
            combined = combined.layeredWith(extractOne(file));
        }
        return combined.toManifest();
    }

    private static boolean isOverrideFile(String name) {
        return name.equals("override.tf") || name.equals("override.tf.json")
                || name.endsWith("_override.tf") || name.endsWith("_override.tf.json");
    }

    private static TerraformKeyedConfigSources extractOne(TerraformConfigIdentity.NamedConfigFile file) {
        try {
            if (file.relativePath().endsWith(".tf.json")) {
                return TerraformJsonSourceExtractor.extractKeyed(file.content());
            }
            return TerraformNativeSourceExtractor.extractKeyed(new String(file.content(), StandardCharsets.UTF_8));
        } catch (TerraformConfigSourceExtractionException e) {
            throw new TerraformConfigSourceExtractionException(file.relativePath() + ": " + e.getMessage());
        }
    }
}
