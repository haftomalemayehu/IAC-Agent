package com.iacagent.iacagent.runner;

/**
 * The fine-grained local-process-execution outcome, kept deliberately separate from the coarser
 * {@link RunnerState} (see {@link RunnerState#TERRAFORM_PROCESS_COMPLETED}). Describes ONLY what
 * happened to the OS process itself - never infrastructure mutation, since none of these values
 * represents one.
 */
public enum TerraformProcessState {
    NOT_STARTED,
    /** The trusted executable's path-safety and SHA-256 checks both passed; the process has not
     * been launched yet. */
    EXECUTABLE_VERIFIED,
    STARTING,
    RUNNING,
    /** The process exited with a code this operation treats as unconditional success. */
    SUCCEEDED,
    /** {@code fmt -check} exited nonzero specifically to report that files would be reformatted -
     * a legitimate, deterministic validation outcome, never treated as a command-execution
     * failure. */
    COMMAND_REPORTED_DIFFERENCE,
    /** The process exited with a code this operation does not treat as success or as a legitimate
     * difference report. */
    FAILED,
    TIMED_OUT,
    OUTPUT_LIMIT_EXCEEDED,
    /** The process was never launched at all - an executable-trust, working-directory, or plan-hash
     * check failed first. */
    BLOCKED
}
