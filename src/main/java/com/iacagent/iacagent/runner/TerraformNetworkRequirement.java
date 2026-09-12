package com.iacagent.iacagent.runner;

/**
 * Explicit, evidence-carried statement of whether an operation might need outbound network access -
 * introduced because {@code terraform init} is the first Phase 2B operation for which "no network"
 * is not automatically true. {@code TERRAFORM_VERSION}/{@code TERRAFORM_FMT_CHECK}/
 * {@code TERRAFORM_SHOW_PLAN_JSON} are always {@link #NONE}; {@code TERRAFORM_INIT} is
 * {@link #PROVIDER_REGISTRY_ONLY} whenever the statically-scanned configuration declares at least
 * one provider source, {@link #NONE} otherwise (a provider-less configuration needs nothing to
 * initialize). {@code TERRAFORM_VALIDATE}/{@code TERRAFORM_PROVIDERS_SCHEMA} carry forward whatever
 * value the init step they ran internally already recorded - see the Phase 2B-4 design doc's
 * "network requirement model" section.
 *
 * <p>This is a policy/evidence value, not an enforcement mechanism: nothing in this package actually
 * opens or blocks a socket. Gate D (production runner sandboxing - OS/container-level network
 * policy) remains open until something outside this package enforces what this value only records.
 */
public enum TerraformNetworkRequirement {
    NONE,
    PROVIDER_REGISTRY_ONLY
}
