package com.iacagent.iacagent.runner;

/** Evidence of where an artifact came from - a reference, never authority by itself. */
public record ArtifactProvenance(String sourceReference) {
    public static final ArtifactProvenance NONE = new ArtifactProvenance(null);
}
