package com.iacagent.iacagent.runner;

/**
 * The closed set of operations {@link ControlledRunner} can be asked to perform. Deliberately
 * contains no mutation operation (no APPLY, no DESTROY, no arbitrary subcommand) - Phase 2B-1
 * grants the runner no infrastructure-mutation authority at all. Adding any such value here is
 * itself a future authority-boundary decision, not something this phase can slide into by adding
 * an enum constant.
 */
public enum RunnerOperation {
    /** Resolve the plan artifact and verify its recomputed hash against both the artifact
     * store's own record and the requested planSha256. Does not check Terraform/provider context. */
    VERIFY_ARTIFACT,
    /** Verify the requested Terraform version and provider-lock hash against runner-observed
     * values. Does not resolve or verify the plan artifact. */
    VERIFY_CONTEXT,
    /** The full Phase 2B-1 pipeline: identity, approval, artifact, and context verification,
     * ending in READY_FOR_FUTURE_EXECUTION. Still performs no execution of any kind. */
    PREPARE_EXECUTION
}
