package com.iacagent.iacagent.runner.jdbc;

import com.iacagent.iacagent.approval.ApprovalValidationReasonCode;
import com.iacagent.iacagent.runner.RunnerEvidence;
import com.iacagent.iacagent.runner.RunnerOperation;
import com.iacagent.iacagent.runner.RunnerRequest;
import com.iacagent.iacagent.runner.RunnerState;
import com.iacagent.iacagent.runner.TerraformPlanEvidence;
import com.iacagent.iacagent.runner.TerraformProcessState;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 2B-5: durable persistence proof for {@link TerraformPlanEvidence} through
 * {@link JdbcRunnerLedgerRepository} - the same "domain semantics covered elsewhere; this file
 * proves a real database round-trip" split established for every prior Terraform evidence type.
 * Also proves credential redaction survives JSON serialization specifically (complementing
 * {@code Phase2b5Tests#credentialValuesNeverAppearInEvidenceOrItsSerializedForm}'s {@code toString()}
 * check), since {@link TerraformPlanEvidenceJson} is package-private and only usable from here.
 */
class Phase2b5JdbcTests {

    private static final Instant NOW = Instant.parse("2026-09-13T00:00:00Z");

    private RunnerRequest sampleRequest(String id) {
        return new RunnerRequest(id, "owner/repository", "c".repeat(40), "nonprod", "config-1",
                "sha256:cfg", "1.6.6", "sha256:lock", "approval-1", RunnerOperation.TERRAFORM_PLAN);
    }

    private TerraformPlanEvidence samplePlanEvidence(RunnerRequest request) {
        return new TerraformPlanEvidence(
                request.runnerRequestId(), "runner-1", request.repository(), request.commitSha(), request.environment(),
                "sha256:config", "sha256:state", "sha256:planinput",
                "sha256:exe-expected", "sha256:exe-observed", "1.6.6", "1.6.6",
                "sha256:lock", "local", "reference-local", "none:local-backend-reference",
                "sha256-abc123", "abc123", 42L, "sha256:showjson", 7L,
                1, 2, 0, 0, 0, false, TerraformProcessState.COMMAND_REPORTED_DIFFERENCE, List.of(),
                NOW, NOW.plusSeconds(3));
    }

    @Test
    void terraformPlanEvidenceRoundTripsThroughARealDatabase(@TempDir Path dir) {
        RunnerRequest request = sampleRequest("req-plan-roundtrip");
        JdbcRunnerLedgerRepository repository = JdbcRunnerLedgerRepository.openH2FileBacked(dir);
        try {
            assertEquals(com.iacagent.iacagent.runner.RunnerClaimOutcome.CLAIMED, repository.claim(request, NOW));
            TerraformPlanEvidence planEvidence = samplePlanEvidence(request);
            RunnerEvidence evidence = new RunnerEvidence(
                    request.runnerRequestId(), "runner-1", "class-a", Set.of("nonprod"), request.requestedOperation(),
                    request.repository(), request.commitSha(), request.environment(), request.planArtifactId(),
                    request.planSha256(), request.planSha256(), request.terraformVersion(), "1.6.6",
                    request.providerLockHash(), request.providerLockHash(), request.approvalId(),
                    ApprovalValidationReasonCode.VALID, RunnerState.TERRAFORM_PROCESS_COMPLETED, List.of(),
                    NOW, NOW.plusSeconds(3), null, null, null, null, planEvidence);
            repository.recordTerminalEvidence(evidence);
        } finally {
            repository.close();
        }

        // Reopen as a fresh object - proves this is a genuine database round-trip, not an in-memory cache.
        JdbcRunnerLedgerRepository reopened = JdbcRunnerLedgerRepository.openH2FileBacked(dir);
        try {
            Optional<RunnerEvidence> found = reopened.findHistoricalEvidence(request.runnerRequestId());
            assertTrue(found.isPresent());
            TerraformPlanEvidence restored = found.get().terraformPlanEvidence();
            assertNotNull(restored);
            assertEquals("sha256:config", restored.configSha256());
            assertEquals("sha256:state", restored.stateIdentitySha256());
            assertEquals("sha256:planinput", restored.planInputSha256());
            assertEquals("sha256-abc123", restored.planArtifactId());
            assertEquals("abc123", restored.planSha256());
            assertEquals(1, restored.createCount());
            assertEquals(2, restored.updateCount());
            assertEquals(TerraformProcessState.COMMAND_REPORTED_DIFFERENCE, restored.processState());
            assertNull(found.get().terraformProcessEvidence());
            assertNull(found.get().terraformInitEvidence());
            assertNull(found.get().terraformValidateEvidence());
            assertNull(found.get().terraformProviderSchemaEvidence());
        } finally {
            reopened.close();
        }
    }

    @Test
    void terraformPlanEvidenceJsonNeverContainsCredentialMaterial() {
        RunnerRequest request = sampleRequest("req-plan-json-redaction");
        TerraformPlanEvidence planEvidence = samplePlanEvidence(request);
        String json = TerraformPlanEvidenceJson.toJson(planEvidence);

        // TerraformPlanEvidence has no field for raw credential values at all - only
        // credentialSourceIdentifier, a non-secret label - so nothing resembling a credential
        // value could ever appear regardless of what a future credential provider might return.
        assertTrue(json.contains("credentialSourceIdentifier"));
        assertTrue(json.contains("none:local-backend-reference"));
        assertFalse(json.toLowerCase().contains("secret"));
        assertFalse(json.toLowerCase().contains("token"));
        assertFalse(json.toLowerCase().contains("password"));

        TerraformPlanEvidence roundTripped = TerraformPlanEvidenceJson.fromJson(json);
        assertEquals(planEvidence.planSha256(), roundTripped.planSha256());
        assertEquals(planEvidence.credentialSourceIdentifier(), roundTripped.credentialSourceIdentifier());
    }
}
