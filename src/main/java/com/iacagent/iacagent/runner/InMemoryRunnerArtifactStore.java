package com.iacagent.iacagent.runner;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Phase 2B-1's deterministic artifact catalog: a fixed set of artifacts pre-staged by test/fixture
 * code, standing in for a real artifact registry (e.g. a CI-produced plan upload) that a later 2B
 * slice will replace. Read-only from {@link ControlledRunner}'s perspective - only test/fixture
 * code populates it, via {@link #stage}.
 */
public final class InMemoryRunnerArtifactStore implements RunnerArtifactStore {

    private final Map<String, StoredArtifact> artifacts = new ConcurrentHashMap<>();

    public void stage(StoredArtifact artifact) {
        artifacts.put(artifact.artifactId(), artifact);
    }

    @Override
    public Optional<StoredArtifact> resolve(String planArtifactId) {
        return Optional.ofNullable(artifacts.get(planArtifactId));
    }
}
