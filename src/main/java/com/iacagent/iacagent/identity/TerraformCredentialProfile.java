package com.iacagent.iacagent.identity;

/**
 * Which credential authority a federation call is requesting - deliberately its own enum, not a
 * boolean or a free-form string, so a future mutation-capable profile can never be introduced by
 * accident (e.g. by silently widening what {@link #PLAN} already grants). Phase 2B-7 defines exactly
 * one value; adding {@code APPLY} (or any other mutation-capable profile) requires its own explicit,
 * separately-reviewed phase - see {@code docs/phase-2b7-workload-identity-federation.md} §11.
 */
public enum TerraformCredentialProfile {
    /** State/provider READ authority only - the sole profile this phase grants. A cloud role
     * resolved for this profile must never carry mutation permissions merely because a future
     * APPLY phase will eventually need them. */
    PLAN
}
