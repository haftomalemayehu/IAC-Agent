package com.iacagent.iacagent;

public record CommandResult(
        String command,
        int exitCode,
        String stdout,
        String stderr,
        String startedAt,
        String finishedAt,
        ValidationState status,
        String errorMessage
) {
    public boolean isSuccessful() {
        return status == ValidationState.PASS;
    }
}
