package com.iacagent.iacagent;

public record PipelineRequest(
        String requestId,
        String repository,
        String workspace,
        String environment,
        String workingDirectory
) {
}
