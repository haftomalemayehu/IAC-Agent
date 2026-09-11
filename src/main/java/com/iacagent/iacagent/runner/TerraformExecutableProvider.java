package com.iacagent.iacagent.runner;

/**
 * The host/runtime boundary that supplies the trusted Terraform executable - the ONLY source
 * anything in this package consults for it. There is no field on {@link RunnerRequest}, no
 * environment {@code PATH} lookup, and no repository-derived path anywhere in this package that
 * could select an executable; a caller cannot influence which binary runs because there is no
 * parameter or code path through which one could attempt to.
 *
 * <p>Must re-resolve and re-validate on EVERY call, never cache - this is the same no-caching, TOCTOU-
 * resistant discipline {@link HostAttestedRunnerIdentityProvider} established in Phase 2B-2 for
 * identity, applied here to executable trust: if the configured path is later replaced (a symlink
 * substituted in, the file swapped for a different one), the very next resolution must reflect that,
 * not a previously-resolved descriptor.
 */
public interface TerraformExecutableProvider {
    TerraformExecutableResolution resolve();
}
