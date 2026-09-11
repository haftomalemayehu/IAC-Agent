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
 * <p>Deliberately excludes {@code INIT}, {@code VALIDATE}, {@code PLAN}, and {@code APPLY} - see
 * {@code docs/phase-2b3-controlled-terraform-process.md} §4 for why each is out of scope for this
 * phase specifically (provider/plugin acquisition, backend initialization, and - for apply -
 * infrastructure mutation itself).
 */
public enum ControlledTerraformOperation {
    /** {@code terraform version -json}. */
    TERRAFORM_VERSION,
    /** {@code terraform fmt -check -no-color -recursive <workspace>}. Never {@code -write}. */
    TERRAFORM_FMT_CHECK,
    /** {@code terraform show -json <staged-plan-path>}. The plan path is always an already
     * hash-verified, runner-staged file - never a caller-supplied or repository path. */
    TERRAFORM_SHOW_PLAN_JSON
}
