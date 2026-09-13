package com.iacagent.iacagent.runner;

import java.util.regex.Pattern;

/**
 * A single trusted, typed Terraform variable input - the shape a future phase would use instead of
 * ever accepting caller-supplied {@code -var}/{@code -var-file} argv. {@code canonicalJsonValue} is
 * expected to already be a canonical JSON value (a single value, not a whole document) for
 * {@code name}; validation here only checks it's non-null, not that it's well-formed JSON, since
 * this type does not itself parse JSON.
 *
 * <p><b>Defined and tested in Phase 2B-5, not yet wired into {@link ControlledTerraformOperationCoordinator#executePlan}.</b>
 * The phase 2B-5 authorization explicitly allows leaving variable support unwired rather than
 * building it loosely; this type exists so {@link TerraformPlanInputIdentity} already has a
 * well-defined, tested slot for variable inputs to bind into once a future phase wires an actual
 * runner-generated {@code .tfvars.json} mechanism - see
 * {@code docs/phase-2b5-controlled-plan-state-read.md} §12.
 */
public record TerraformVariableInput(String name, String canonicalJsonValue, boolean sensitive) {

    private static final Pattern VALID_NAME = Pattern.compile("[A-Za-z_][A-Za-z0-9_-]*");

    public TerraformVariableInput {
        if (name == null || !VALID_NAME.matcher(name).matches()) {
            throw new IllegalArgumentException("variable name is not a valid Terraform identifier: " + name);
        }
        if (canonicalJsonValue == null) {
            throw new IllegalArgumentException("canonicalJsonValue is required");
        }
    }

    /** What is safe to ever put in evidence/logs: the name and whether it's sensitive, never the
     * value itself when {@code sensitive} is true. */
    public String redactedDescription() {
        return name + "=" + (sensitive ? "[REDACTED]" : canonicalJsonValue);
    }
}
