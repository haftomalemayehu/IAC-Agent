package com.iacagent.iacagent.runner;

/**
 * Models how {@code terraform init} is allowed to treat backend configuration. Phase 2B-4
 * implements and permits exactly one value - {@link #LOCAL_ONLY} - which is enforced by
 * {@link TerraformCommandFactory#initCommand} always constructing {@code -backend=false} into the
 * argv regardless of what any caller or repository content might want; the other two values exist
 * so the policy shape is explicit and forward-looking, not because this phase can act on them.
 *
 * <p>{@link ControlledTerraformOperationCoordinator#executeInit} rejects any configured mode other
 * than {@link #LOCAL_ONLY} with {@link RunnerReasonCode#TERRAFORM_BACKEND_MODE_UNSAFE} BEFORE ever
 * building or launching the init command - a backend-enabled path was explicitly named in the
 * Phase 2B-4 authorization as something to stop and report on rather than implement, so this is a
 * hard, structural refusal, not a soft default that something could accidentally widen.
 */
public enum TerraformBackendMode {
    /** {@code -backend=false} - the only mode this phase actually runs. No remote state access,
     * no state locking, no backend credentials of any kind are ever involved. */
    LOCAL_ONLY,
    /** Not implemented. A backend could be initialized read-only (e.g. to resolve provider
     * requirements without ever writing state) - deliberately not built in this phase; see the
     * Phase 2B-4 design doc's "backend policy" section for why. */
    REMOTE_READONLY_INIT,
    /** Not implemented, and not a near-term goal - full backend initialization implies remote
     * state credentials and state mutation risk, both explicitly out of scope through at least
     * Phase 2A runtime. */
    REMOTE_ALLOWED
}
