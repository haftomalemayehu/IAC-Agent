package com.iacagent.iacagent.runner;

/**
 * Deliberately contains no APPLYING/APPLIED/MUTATED state - no phase through 2B-3 grants mutation
 * authority, so no state exists to represent one. {@code READY_FOR_FUTURE_EXECUTION} and (as of
 * Phase 2B-3) {@code TERRAFORM_PROCESS_COMPLETED} are as far as this phase's state machine goes; a
 * later phase, not this enum being extended casually, is what would ever move past them.
 */
public enum RunnerState {
    RECEIVED,
    /** The durable ledger has atomically claimed this runnerRequestId - added in Phase 2B-2, since
     * a claim can now fail closed (RUNNER_LEDGER_UNAVAILABLE, duplicate, fingerprint mismatch,
     * incomplete prior claim) before identity is ever resolved. */
    REQUEST_CLAIMED,
    IDENTITY_RESOLVED,
    APPROVAL_RESOLVED,
    ARTIFACT_RESOLVED,
    ARTIFACT_VERIFIED,
    CONTEXT_VERIFIED,
    READY_FOR_FUTURE_EXECUTION,
    /** Phase 2B-3: a {@code TERRAFORM_VERSION}/{@code TERRAFORM_FMT_CHECK}/
     * {@code TERRAFORM_SHOW_PLAN_JSON} process ran to a determinate, evidence-recorded conclusion -
     * including a legitimate non-error outcome such as {@code fmt -check} reporting formatting
     * differences (see {@link TerraformProcessState#COMMAND_REPORTED_DIFFERENCE}, which carries that
     * finer-grained distinction in {@link RunnerEvidence#terraformProcessEvidence()} - this coarser
     * {@code RunnerState} value only means "the process boundary produced trustworthy evidence,"
     * not "the command found nothing to report." Never reached if the executable trust/hash check,
     * the process launch itself, a timeout, or an output-limit violation failed first - those remain
     * {@link #BLOCKED}. */
    TERRAFORM_PROCESS_COMPLETED,
    BLOCKED,
    FAILED
}
