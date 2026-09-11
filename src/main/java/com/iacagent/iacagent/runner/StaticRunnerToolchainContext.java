package com.iacagent.iacagent.runner;

public final class StaticRunnerToolchainContext implements RunnerToolchainContext {

    private final String terraformVersion;
    private final String providerLockHash;

    public StaticRunnerToolchainContext(String terraformVersion, String providerLockHash) {
        if (terraformVersion == null || terraformVersion.isBlank()) {
            throw new IllegalArgumentException("terraformVersion is required");
        }
        if (providerLockHash == null || providerLockHash.isBlank()) {
            throw new IllegalArgumentException("providerLockHash is required");
        }
        this.terraformVersion = terraformVersion;
        this.providerLockHash = providerLockHash;
    }

    @Override
    public String observedTerraformVersion() {
        return terraformVersion;
    }

    @Override
    public String observedProviderLockHash() {
        return providerLockHash;
    }
}
