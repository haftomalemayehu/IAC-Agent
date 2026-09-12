package com.iacagent.iacagent.runner;

/**
 * The closed set of Terraform commands {@link TerraformCommandFactory} can construct an argv for.
 * Deliberately a SEPARATE type from {@link RunnerOperation} (which has a correspondingly-named
 * value for each of these): this type, and everything downstream of it ({@link TerraformCommandFactory},
 * {@link ControlledTerraformProcess}), is usable and testable entirely on its own, with no
 * dependency on {@link RunnerRequest}, {@link ControlledRunner}, or the approval/ledger machinery -
 * {@link ControlledRunner} is simply the only production caller that ever constructs one, mapping
 * its own {@link RunnerOperation} value across.
 *
 * <p>Phase 2B-4 adds {@code TERRAFORM_INIT}/{@code TERRAFORM_VALIDATE}/{@code TERRAFORM_PROVIDERS_SCHEMA} -
 * see {@code docs/phase-2b4-controlled-init-validation.md} for the trust model governing them
 * (provider/module source policy, backend mode, lockfile discipline, configuration identity). Still
 * deliberately excludes {@code PLAN} and {@code APPLY} - infrastructure mutation itself, and the
 * plan-generation step that would precede it, remain unrepresentable by any value of this enum.
 */
public enum ControlledTerraformOperation {
    /** {@code terraform version -json}. */
    TERRAFORM_VERSION,
    /** {@code terraform fmt -check -no-color -recursive <workspace>}. Never {@code -write}. */
    TERRAFORM_FMT_CHECK,
    /** {@code terraform show -json <staged-plan-path>}. The plan path is always an already
     * hash-verified, runner-staged file - never a caller-supplied or repository path. */
    TERRAFORM_SHOW_PLAN_JSON,
    /** {@code terraform init -backend=false -input=false -no-color -lockfile=readonly}. Phase
     * 2B-4's new trust boundary - see {@code docs/phase-2b4-controlled-init-validation.md} §"Init
     * is a new trust boundary." */
    TERRAFORM_INIT,
    /** {@code terraform validate -json -no-color}. Always preceded, within the same coordinator
     * call, by a successful {@link #TERRAFORM_INIT} against the identical staged configuration. */
    TERRAFORM_VALIDATE,
    /** {@code terraform providers schema -json}. Always preceded, within the same coordinator
     * call, by a successful {@link #TERRAFORM_INIT} against the identical staged configuration. */
    TERRAFORM_PROVIDERS_SCHEMA
}
