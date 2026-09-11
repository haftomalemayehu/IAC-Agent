package com.iacagent.iacagent.runner;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * A LOCAL/REFERENCE host-attestation identity source - explicitly NOT a production-grade identity
 * mechanism. Identity is read from a location fixed at construction time by trusted bootstrap code
 * (an operator, an orchestrator, a host-level provisioning step) - never a {@link RunnerRequest}
 * field, and structurally never influenced by one, since {@link #currentIdentity()} takes zero
 * parameters. Production execution authority requires real workload identity/OIDC (Gate C,
 * {@code docs/phase-2b2-runner-hardening.md} §15), which this class does not attempt to satisfy.
 *
 * <h2>Trust model</h2>
 * Request-independence alone does not establish host attestation: a plain local file is only as
 * trustworthy as whoever can make {@code identityFile}'s path resolve there. Two review rounds
 * hardened this class against exactly that gap:
 * <ul>
 *   <li><b>Round 1</b> added a single {@code excludedWorkspaceRoot} exclusion and a leaf-level
 *       symlink check - sufficient to stop a workspace or a direct symlink substitution from
 *       supplying identity, but not sufficient against a symlink planted in an ANCESTOR directory
 *       component (e.g. a trusted-looking {@code /opt/iac-agent/identity/runner.json} where
 *       {@code /opt/iac-agent/identity} itself has been replaced with a symlink into a
 *       repository-controlled directory - {@code runner.json} itself is a perfectly ordinary
 *       regular file, so a leaf-only symlink check would never notice), and it had no explicit
 *       concept of a repository-checkout root at all.
 *   <li><b>Round 2</b> (this revision) replaces the single exclusion with an explicit
 *       {@code trustedIdentityRoot} + {@code untrustedRoots} model, and moves the safety check from
 *       "is the leaf path a symlink" to "does this path's fully-resolved real location still fall
 *       under the trusted root, and NOT under any untrusted root" - which catches ancestor-symlink
 *       redirection as a side effect of catching the more general "where does this path actually,
 *       physically point right now" question.
 * </ul>
 *
 * <h2>What is enforced</h2>
 * <ul>
 *   <li>{@code trustedIdentityRoot} is resolved to its real path ({@link Path#toRealPath}) ONCE, at
 *       construction, by the trusted bootstrap code that calls this constructor - the assumption
 *       (inherent to "trusted bootstrap") is that the filesystem is not already under adversarial
 *       control at that exact moment. Construction fails (`IllegalArgumentException`) if this path
 *       does not resolve to a real, existing directory.
 *   <li>Each entry in {@code untrustedRoots} (expected to include at minimum the runner's own
 *       workspace root and any repository-checkout root) is similarly resolved once at construction
 *       - best-effort, falling back to a normalized absolute path if the root does not exist yet.
 *       Construction fails if {@code trustedIdentityRoot} itself resolves underneath any untrusted
 *       root (a direct contradiction - an untrusted root is allowed to nest INSIDE the trusted root,
 *       since that is a legitimate "trusted install directory that happens to also contain
 *       subdirectories we still don't want to trust for identity" shape, but not the reverse).
 *   <li>{@code identityFile} must, at construction, textually resolve under {@code trustedIdentityRoot}
 *       - checked before the file necessarily exists, so a plainly-misconfigured path fails loudly
 *       immediately rather than only once someone notices identity is always unavailable.
 *   <li>On EVERY {@link #currentIdentity()} call (no caching): the leaf path itself is rejected
 *       outright if it is a symlink ({@link Files#isSymbolicLink}), independent of where that
 *       symlink points - even a symlink to an otherwise-valid file under the trusted root is
 *       rejected, because "this exact path is not supposed to be a symlink" is itself part of the
 *       invariant, not merely a proxy for "does it point somewhere bad." Then {@code identityFile}
 *       is resolved to its CURRENT real path ({@link Path#toRealPath}, re-resolved fresh every
 *       call - this is what catches ancestor-directory symlink substitution introduced after
 *       construction, since the real path of a file reached through a since-redirected ancestor
 *       directory changes to reflect the redirection) and that real path must fall under the
 *       construction-time trusted root and under none of the untrusted roots.
 *   <li>The final resolved file must be a regular, readable file; any other failure (missing, not a
 *       regular file, unreadable, malformed JSON, a required field absent) collapses to
 *       {@link Optional#empty()}, never a partial or default identity.
 * </ul>
 *
 * <h2>What is still NOT attempted</h2>
 * Filesystem ownership/POSIX-permission verification, and any cryptographic signature/measurement
 * over the file's content - neither can be done reliably/portably within this phase's scope, and
 * this javadoc says so rather than implying a stronger guarantee than the class provides. This
 * remains a local/reference attestation mechanism; Gate C (real workload identity/OIDC) is unchanged
 * and still open.
 */
public final class HostAttestedRunnerIdentityProvider implements RunnerIdentityProvider {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Path identityFile;
    private final Path trustedIdentityRootReal;
    private final List<Path> untrustedRootsReal;

    /**
     * @param identityFile      the local attestation source, fixed by trusted bootstrap code -
     *                          never a value derived from a {@link RunnerRequest}. Must textually
     *                          resolve under {@code trustedIdentityRoot}.
     * @param trustedIdentityRoot the directory trusted bootstrap code vouches for; resolved to its
     *                          real path once, at construction.
     * @param untrustedRoots    roots that must NEVER be where {@code identityFile} actually,
     *                          physically resolves to - expected to include at least the runner's
     *                          workspace root and any repository-checkout root. May be empty, never
     *                          null, and must not itself contain a null entry.
     */
    public HostAttestedRunnerIdentityProvider(Path identityFile, Path trustedIdentityRoot, List<Path> untrustedRoots) {
        if (identityFile == null) {
            throw new IllegalArgumentException("identityFile is required");
        }
        if (trustedIdentityRoot == null) {
            throw new IllegalArgumentException("trustedIdentityRoot is required");
        }
        if (untrustedRoots == null) {
            throw new IllegalArgumentException("untrustedRoots is required (may be empty, never null)");
        }
        this.trustedIdentityRootReal = resolveTrustedRoot(trustedIdentityRoot);
        this.untrustedRootsReal = untrustedRoots.stream().map(HostAttestedRunnerIdentityProvider::resolveUntrustedRoot).toList();
        for (Path untrusted : untrustedRootsReal) {
            if (trustedIdentityRootReal.startsWith(untrusted)) {
                throw new IllegalArgumentException(
                        "trustedIdentityRoot must not resolve underneath an untrusted root - trustedIdentityRoot="
                                + trustedIdentityRootReal + ", untrustedRoot=" + untrusted);
            }
        }
        // Compared against the SAME kind of resolved path used for trustedIdentityRootReal/
        // untrustedRootsReal (best-effort real path, not a plain normalize()) - on platforms where
        // the OS temp/system directory itself is a symlink (e.g. macOS's /var -> /private/var), a
        // real-path-resolved root and a merely-normalized (non-real-path) leaf path can textually
        // disagree on their common prefix even though they point at the same actual location.
        Path resolvedIdentityFileParent = resolveBestEffort(requireNonNullPath(identityFile.toAbsolutePath().normalize().getParent(), "identityFile"));
        if (!resolvedIdentityFileParent.startsWith(trustedIdentityRootReal)) {
            throw new IllegalArgumentException(
                    "identityFile must reside under trustedIdentityRoot: " + identityFile + " is not under " + trustedIdentityRoot);
        }
        this.identityFile = identityFile;
    }

    private static Path requireNonNullPath(Path path, String name) {
        if (path == null) {
            throw new IllegalArgumentException(name + " must have a parent directory");
        }
        return path;
    }

    private static Path resolveTrustedRoot(Path trustedIdentityRoot) {
        try {
            return trustedIdentityRoot.toRealPath();
        } catch (IOException e) {
            throw new IllegalArgumentException(
                    "trustedIdentityRoot must resolve to a real, existing directory: " + trustedIdentityRoot, e);
        }
    }

    private static Path resolveUntrustedRoot(Path root) {
        if (root == null) {
            throw new IllegalArgumentException("an untrusted root must not be null");
        }
        return resolveBestEffort(root);
    }

    /**
     * Resolves {@code path} to a real path where possible; if {@code path} itself does not exist
     * yet, walks up to the nearest EXISTING ancestor, resolves that ancestor's real path, and
     * re-appends the missing suffix components textually. A plain
     * {@code path.toAbsolutePath().normalize()} fallback would be wrong whenever an existing
     * ancestor sits behind an OS-level symlink the JVM's absolute-path computation does not itself
     * resolve (e.g. macOS's {@code /var} -&gt; {@code /private/var}): a real-path-resolved sibling
     * and a merely-normalized descendant of the very same directory would then disagree on their
     * textual prefix even though both point at the same actual location. This does not detect a
     * symlink planted in one of the NOT-YET-EXISTING suffix components before they are created -
     * an accepted limitation of a reference-grade, not production-grade, provider.
     */
    private static Path resolveBestEffort(Path path) {
        Path absolute = path.toAbsolutePath().normalize();
        try {
            return absolute.toRealPath();
        } catch (IOException e) {
            // fall through to the nearest-existing-ancestor walk below
        }
        Path suffix = null;
        Path ancestor = absolute;
        while (ancestor != null && !Files.exists(ancestor)) {
            Path name = ancestor.getFileName();
            suffix = suffix == null ? name : name.resolve(suffix);
            ancestor = ancestor.getParent();
        }
        if (ancestor == null) {
            return absolute; // no existing ancestor at all (e.g. even the filesystem root is missing) - give up
        }
        try {
            Path realAncestor = ancestor.toRealPath();
            return suffix == null ? realAncestor : realAncestor.resolve(suffix);
        } catch (IOException e) {
            return absolute;
        }
    }

    @Override
    public Optional<RunnerIdentity> currentIdentity() {
        try {
            // Rejected outright, independent of where it points - even a symlink to an otherwise-
            // valid file under the trusted root is not acceptable, because the leaf path itself is
            // not supposed to be a symlink at all.
            if (Files.isSymbolicLink(identityFile)) {
                return Optional.empty();
            }
            Path real;
            try {
                real = identityFile.toRealPath();
            } catch (IOException e) {
                return Optional.empty(); // missing, or an ancestor component is broken/unresolvable
            }
            if (!real.startsWith(trustedIdentityRootReal)) {
                // Catches ancestor-directory symlink redirection introduced after construction: if
                // any path component between the trusted root and this file has since been replaced
                // by a symlink, the freshly-resolved real path no longer falls under the
                // construction-time trusted root, even though identityFile's own path string (and
                // its own leaf symlink-ness) never changed.
                return Optional.empty();
            }
            for (Path untrusted : untrustedRootsReal) {
                if (real.startsWith(untrusted)) {
                    return Optional.empty();
                }
            }
            if (!Files.isRegularFile(real)) {
                return Optional.empty();
            }
            if (!Files.isReadable(real)) {
                return Optional.empty();
            }
            JsonNode root = MAPPER.readTree(Files.readString(real));
            String runnerId = textOrNull(root, "runnerId");
            String runnerClass = textOrNull(root, "runnerClass");
            if (runnerId == null || runnerClass == null) {
                return Optional.empty();
            }
            boolean trusted = root.path("trusted").asBoolean(false);
            Set<String> environmentScope = new LinkedHashSet<>();
            for (JsonNode entry : root.path("environmentScope")) {
                environmentScope.add(entry.asText());
            }
            return Optional.of(new RunnerIdentity(runnerId, runnerClass, environmentScope, trusted));
        } catch (IOException | RuntimeException e) {
            return Optional.empty();
        }
    }

    private static String textOrNull(JsonNode root, String field) {
        JsonNode node = root.path(field);
        return node.isMissingNode() || node.isNull() ? null : node.asText();
    }
}
