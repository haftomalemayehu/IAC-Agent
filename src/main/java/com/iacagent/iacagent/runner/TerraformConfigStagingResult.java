package com.iacagent.iacagent.runner;

import java.nio.file.Path;
import java.util.List;

/**
 * The result of {@link RunnerWorkspaceManager#stageTerraformConfigDirectory}: either every
 * discovered {@code .tf} file was safely staged ({@code stagedFiles} populated, {@code failureReason}
 * null), or the whole attempt was rejected as one atomic outcome ({@code stagedFiles} empty,
 * {@code failureReason} set) - there is no partial-success case, since a source tree that fails
 * safety validation partway through must not leave some of its content staged and trusted while
 * the rest is rejected.
 */
public record TerraformConfigStagingResult(List<Path> stagedFiles, RunnerReasonCode failureReason) {

    public TerraformConfigStagingResult {
        stagedFiles = stagedFiles == null ? List.of() : List.copyOf(stagedFiles);
    }

    public boolean isSuccess() {
        return failureReason == null;
    }

    static TerraformConfigStagingResult success(List<Path> stagedFiles) {
        return new TerraformConfigStagingResult(stagedFiles, null);
    }

    static TerraformConfigStagingResult failure(RunnerReasonCode reason) {
        if (reason == null) {
            throw new IllegalArgumentException("reason is required for a failed staging result");
        }
        return new TerraformConfigStagingResult(List.of(), reason);
    }
}
