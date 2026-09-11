package com.iacagent.iacagent.runner;

/**
 * The outcome of {@link TerraformExecutableProvider#resolve()}. Deliberately does not include a
 * hash-mismatch value: hash verification requires actually reading the resolved file's bytes, which
 * is the caller's job (it needs the same bytes to compute the SHA-256 comparison itself) - a
 * successful {@link #RESOLVED} here means only "this path is safe to read and execute," never "this
 * is the exact trusted binary." That determination is finished only after the caller compares the
 * recomputed hash against {@link TerraformExecutableDescriptor#expectedSha256()}.
 */
public enum TerraformExecutableResolutionOutcome {
    /** The configured executable path is safe: not a symlink, resolves under the trusted tool
     * root, resolves under no configured untrusted root, and is a regular, executable file. */
    RESOLVED,
    /** No file exists at the configured path (or an ancestor component could not be resolved). */
    NOT_FOUND,
    /** The path exists but failed a path-safety check - it is itself a symlink, or its real
     * location falls outside the trusted tool root, or inside a configured untrusted root. */
    UNTRUSTED_PATH,
    /** The path-safety-verified file is not a regular, executable file (e.g. a directory, or
     * missing the executable permission bit). */
    NOT_EXECUTABLE
}
