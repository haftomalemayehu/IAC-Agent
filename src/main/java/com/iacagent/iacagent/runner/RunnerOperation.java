package com.iacagent.iacagent.runner;

/**
 * The closed set of operations {@link ControlledRunner} can be asked to perform. Deliberately
 * contains no mutation operation (no APPLY, no DESTROY, no arbitrary subcommand) - Phase 2B-1
 * grants the runner no infrastructure-mutation authority at all, and Phase 2B-3's three additions
 * below launch a real Terraform process for the first time but remain equally non-mutating (no
 * {@code init}/{@code validate}/{@code plan}/{@code apply} - see
 * {@code docs/phase-2b3-controlled-terraform-process.md} §4 for why those four are deliberately
 * excluded from this phase). Adding a mutation value here is itself a future authority-boundary
 * decision, not something any phase can slide into by adding an enum constant.
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
    PREPARE_EXECUTION,
    /** Phase 2B-3: launches the trusted Terraform executable with {@code version -json} and
     * verifies its reported version against the runner's pinned expectation. Consumes no plan
     * artifact - the request is still scoped to a specific approval/plan context, but this
     * operation itself only asks "is the trusted binary the version we expect." */
    TERRAFORM_VERSION,
    /** Phase 2B-3: stages the request's bound Terraform configuration content (resolved and
     * hash-verified exactly like {@link #VERIFY_ARTIFACT}, via {@link RunnerArtifactStore}) into
     * the workspace and runs {@code terraform fmt -check -no-color -recursive} against it. Never
     * writes/reformats - {@code -check} only. */
    TERRAFORM_FMT_CHECK,
    /** Phase 2B-3: runs {@code terraform show -json} against the already-verified, staged plan
     * artifact only - never an arbitrary or caller-supplied path. Re-verifies the staged plan's
     * SHA-256 immediately before launching the process (a final TOCTOU check on top of the
     * artifact verification already performed earlier in the pipeline). */
    TERRAFORM_SHOW_PLAN_JSON,
    /** Phase 2B-4: stages the request's bound Terraform configuration content (same resolution
     * path as {@link #TERRAFORM_FMT_CHECK}) and runs a policy-governed {@code terraform init
     * -backend=false -input=false -no-color -lockfile=readonly} against it. Still no {@code plan}/
     * {@code apply}/backend/state capability of any kind - see
     * {@code docs/phase-2b4-controlled-init-validation.md}. */
    TERRAFORM_INIT,
    /** Phase 2B-4: internally runs the same controlled {@code init} sequence as
     * {@link #TERRAFORM_INIT} against the staged configuration, then - only if that succeeds -
     * runs {@code terraform validate -json}. Never runs validate against a configuration that
     * was not just successfully, freshly initialized in this same call. */
    TERRAFORM_VALIDATE,
    /** Phase 2B-4: internally runs the same controlled {@code init} sequence as
     * {@link #TERRAFORM_INIT} against the staged configuration, then - only if that succeeds -
     * runs {@code terraform providers schema -json}. Never runs against a configuration that was
     * not just successfully, freshly initialized in this same call. */
    TERRAFORM_PROVIDERS_SCHEMA,
    /** Phase 2B-5: stages the request's bound Terraform configuration (same resolution path as
     * {@link #TERRAFORM_FMT_CHECK}), resolves a trusted backend/state target via
     * {@link TrustedBackendResolver}, runs a controlled {@code init} against that REAL backend
     * (never {@code -backend=false}), then {@code terraform plan -out=<runner-owned-path>}. Produces
     * a durable, hash-bound saved-plan artifact. Never applies, never writes state intentionally,
     * never mutates infrastructure. */
    TERRAFORM_PLAN
}
