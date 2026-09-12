package com.iacagent.iacagent.runner;

import java.time.Instant;
import java.util.List;

/**
 * The structured result of one {@code TERRAFORM_PROVIDERS_SCHEMA} coordinator call. Like
 * {@link TerraformValidateEvidence}, embeds the internally-run {@code TERRAFORM_INIT} attempt's
 * evidence that gated it, and binds {@code configSha256}/{@code lockfileHash} (the lockfile hash
 * AFTER that same init step, i.e. the exact lockfile state {@code providers schema} actually ran
 * under) so schema output is never treated as authoritative for a configuration/lockfile/executable
 * identity other than the one it was actually produced against.
 *
 * <p>The schema JSON itself is deliberately not embedded here - only its size and hash, per this
 * package's established convention of never persisting arbitrary tool output. A caller needing the
 * actual schema content would capture it from the coordinator's raw {@link TerraformProcessResult}
 * at the point of the call, same as any other bounded process artifact in this package.
 */
public record TerraformProviderSchemaEvidence(
        String runnerRequestId,
        String runnerId,
        TerraformInitEvidence initEvidence,
        String configSha256,
        String lockfileHash,
        List<String> providerSourceIdentities,
        String schemaJsonSha256,
        long schemaJsonSize,
        String terraformVersionObserved,
        Integer exitCode,
        boolean timedOut,
        TerraformProcessState processState,
        List<RunnerReasonCode> reasonCodes,
        Instant startedAt,
        Instant completedAt
) {
    public TerraformProviderSchemaEvidence {
        if (initEvidence == null) {
            throw new IllegalArgumentException("initEvidence is required - providers schema never runs without an init attempt of some outcome");
        }
        if (processState == null) {
            throw new IllegalArgumentException("processState is required");
        }
        reasonCodes = reasonCodes == null ? List.of() : List.copyOf(reasonCodes);
        providerSourceIdentities = providerSourceIdentities == null ? List.of() : List.copyOf(providerSourceIdentities);
    }
}
