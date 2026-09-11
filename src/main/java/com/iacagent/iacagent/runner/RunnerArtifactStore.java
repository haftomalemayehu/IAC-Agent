package com.iacagent.iacagent.runner;

import java.util.Optional;

/**
 * Resolves a {@code planArtifactId} to its actual bytes. This is the ONLY way
 * {@link ControlledRunner} obtains artifact content - there is no method anywhere in this package
 * that fetches a URL supplied by a {@link RunnerRequest}, because no such field or code path
 * exists. A missing artifact id returns {@link Optional#empty()}, never a default/empty artifact.
 */
public interface RunnerArtifactStore {
    Optional<StoredArtifact> resolve(String planArtifactId);
}
