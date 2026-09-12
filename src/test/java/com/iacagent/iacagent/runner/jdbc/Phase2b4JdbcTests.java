package com.iacagent.iacagent.runner.jdbc;

import com.iacagent.iacagent.approval.ApprovalValidationReasonCode;
import com.iacagent.iacagent.runner.RunnerEvidence;
import com.iacagent.iacagent.runner.RunnerOperation;
import com.iacagent.iacagent.runner.RunnerRequest;
import com.iacagent.iacagent.runner.RunnerState;
import com.iacagent.iacagent.runner.TerraformBackendMode;
import com.iacagent.iacagent.runner.TerraformInitEvidence;
import com.iacagent.iacagent.runner.TerraformNetworkRequirement;
import com.iacagent.iacagent.runner.TerraformProcessState;
import com.iacagent.iacagent.runner.TerraformProviderSchemaEvidence;
import com.iacagent.iacagent.runner.TerraformValidateEvidence;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 2B-4: durable persistence proof for the three new embedded evidence records
 * ({@link TerraformInitEvidence}, {@link TerraformValidateEvidence}, {@link TerraformProviderSchemaEvidence})
 * through {@link JdbcRunnerLedgerRepository} - the same "domain semantics already covered elsewhere;
 * this file proves they survive a real database round-trip" split {@code Phase2b2JdbcTests}
 * established for {@code TerraformProcessEvidence} in Phase 2B-3.
 */
class Phase2b4JdbcTests {

    private static final Instant NOW = Instant.parse("2026-09-11T00:00:00Z");

    private RunnerRequest sampleRequest(String id) {
        return new RunnerRequest(id, "owner/repository", "c".repeat(40), "nonprod", "config-1",
                "sha256:cfg", "1.6.6", "sha256:lock", "approval-1", RunnerOperation.TERRAFORM_VALIDATE);
    }

    private TerraformInitEvidence sampleInitEvidence(RunnerRequest request) {
        return new TerraformInitEvidence(
                request.runnerRequestId(), "runner-1", "sha256:config", "sha256:exe-expected", "sha256:exe-observed",
                "1.6.6", "1.6.6", TerraformBackendMode.LOCAL_ONLY, TerraformNetworkRequirement.NONE,
                List.of(), List.of(), null, null, 0, false, TerraformProcessState.SUCCEEDED, List.of(),
                0, 0, "sha256:empty", "sha256:empty", NOW, NOW.plusSeconds(1));
    }

    @Test
    void terraformValidateEvidenceRoundTripsThroughARealDatabase(@TempDir Path dir) {
        RunnerRequest request = sampleRequest("req-validate-roundtrip");
        JdbcRunnerLedgerRepository repository = JdbcRunnerLedgerRepository.openH2FileBacked(dir);
        try {
            assertEquals(com.iacagent.iacagent.runner.RunnerClaimOutcome.CLAIMED, repository.claim(request, NOW));

            TerraformInitEvidence initEvidence = sampleInitEvidence(request);
            TerraformValidateEvidence validateEvidence = new TerraformValidateEvidence(
                    request.runnerRequestId(), "runner-1", initEvidence, initEvidence.configSha256(),
                    true, 0, 0, List.of("fingerprint-1"), 0, false, TerraformProcessState.SUCCEEDED, List.of(),
                    "sha256:stdout", NOW, NOW.plusSeconds(2));
            RunnerEvidence evidence = new RunnerEvidence(
                    request.runnerRequestId(), "runner-1", "class-a", Set.of("nonprod"), request.requestedOperation(),
                    request.repository(), request.commitSha(), request.environment(), request.planArtifactId(),
                    request.planSha256(), request.planSha256(), request.terraformVersion(), "1.6.6",
                    request.providerLockHash(), request.providerLockHash(), request.approvalId(),
                    ApprovalValidationReasonCode.VALID, RunnerState.TERRAFORM_PROCESS_COMPLETED, List.of(),
                    NOW, NOW.plusSeconds(2), null, null, validateEvidence, null);
            repository.recordTerminalEvidence(evidence);
        } finally {
            repository.close();
        }

        // Reopen as a fresh object - proves this is a genuine database round-trip, not an in-memory cache.
        JdbcRunnerLedgerRepository reopened = JdbcRunnerLedgerRepository.openH2FileBacked(dir);
        try {
            Optional<RunnerEvidence> found = reopened.findHistoricalEvidence(request.runnerRequestId());
            assertTrue(found.isPresent());
            TerraformValidateEvidence restored = found.get().terraformValidateEvidence();
            assertNotNull(restored);
            assertEquals(Boolean.TRUE, restored.valid());
            assertEquals(List.of("fingerprint-1"), restored.diagnosticFingerprints());
            assertNotNull(restored.initEvidence());
            assertEquals("sha256:config", restored.initEvidence().configSha256());
            assertEquals(TerraformBackendMode.LOCAL_ONLY, restored.initEvidence().backendMode());
            assertEquals(TerraformNetworkRequirement.NONE, restored.initEvidence().networkRequirement());
            assertNull(found.get().terraformProcessEvidence());
            assertNull(found.get().terraformInitEvidence());
            assertNull(found.get().terraformProviderSchemaEvidence());
        } finally {
            reopened.close();
        }
    }

    @Test
    void terraformInitEvidenceRoundTripsThroughARealDatabase(@TempDir Path dir) {
        RunnerRequest request = sampleRequest("req-init-roundtrip");
        JdbcRunnerLedgerRepository repository = JdbcRunnerLedgerRepository.openH2FileBacked(dir);
        try {
            assertEquals(com.iacagent.iacagent.runner.RunnerClaimOutcome.CLAIMED, repository.claim(request, NOW));
            TerraformInitEvidence initEvidence = sampleInitEvidence(request);
            RunnerEvidence evidence = new RunnerEvidence(
                    request.runnerRequestId(), "runner-1", "class-a", Set.of("nonprod"), RunnerOperation.TERRAFORM_INIT,
                    request.repository(), request.commitSha(), request.environment(), request.planArtifactId(),
                    request.planSha256(), request.planSha256(), request.terraformVersion(), "1.6.6",
                    request.providerLockHash(), request.providerLockHash(), request.approvalId(),
                    ApprovalValidationReasonCode.VALID, RunnerState.TERRAFORM_PROCESS_COMPLETED, List.of(),
                    NOW, NOW.plusSeconds(1), null, initEvidence, null, null);
            repository.recordTerminalEvidence(evidence);
        } finally {
            repository.close();
        }

        JdbcRunnerLedgerRepository reopened = JdbcRunnerLedgerRepository.openH2FileBacked(dir);
        try {
            Optional<RunnerEvidence> found = reopened.findHistoricalEvidence(request.runnerRequestId());
            assertTrue(found.isPresent());
            TerraformInitEvidence restored = found.get().terraformInitEvidence();
            assertNotNull(restored);
            assertEquals("sha256:config", restored.configSha256());
            assertEquals(TerraformProcessState.SUCCEEDED, restored.processState());
        } finally {
            reopened.close();
        }
    }
}
