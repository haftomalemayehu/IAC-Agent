package com.iacagent.iacagent.runner.jdbc;

import com.iacagent.iacagent.approval.InMemoryApprovalRepository;
import com.iacagent.iacagent.approval.RepositoryBackedApprovalProvider;
import com.iacagent.iacagent.runner.ControlledRunner;
import com.iacagent.iacagent.runner.ControlledTerraformOperation;
import com.iacagent.iacagent.runner.InMemoryRunnerArtifactStore;
import com.iacagent.iacagent.runner.RunnerClaimOutcome;
import com.iacagent.iacagent.runner.RunnerEvidence;
import com.iacagent.iacagent.runner.RunnerIdentity;
import com.iacagent.iacagent.runner.RunnerLedgerRepository;
import com.iacagent.iacagent.runner.RunnerOperation;
import com.iacagent.iacagent.runner.RunnerReasonCode;
import com.iacagent.iacagent.runner.RunnerRequest;
import com.iacagent.iacagent.runner.RunnerState;
import com.iacagent.iacagent.runner.RunnerToolchainContext;
import com.iacagent.iacagent.runner.RunnerWorkspaceManager;
import com.iacagent.iacagent.runner.StaticRunnerIdentityProvider;
import com.iacagent.iacagent.runner.StaticRunnerToolchainContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 2B-6 unit tests (no real database - see {@code com.iacagent.iacagent.runner.jdbc.Phase2b6PostgresAcceptanceTests}
 * in the separate {@code postgresTest} source set for the real-PostgreSQL concurrency/restart/
 * outage/migration acceptance suite that is Gate B's actual closure evidence). Covers: the new
 * {@link RunnerClaimOutcome#AMBIGUOUS} outcome's wiring through {@link ControlledRunner}, production
 * configuration validation/fail-closed behavior ({@link RunnerLedgerConfiguration},
 * {@link PostgresRunnerLedgerConfig}, {@link RunnerLedgerTlsMode}), credential-source behavior, and
 * secret-redaction in configuration diagnostics/{@code toString()}.
 */
class Phase2b6Tests {

    private static final Instant NOW = Instant.parse("2026-09-14T00:00:00Z");
    private static final String REPOSITORY = "owner/repository";
    private static final String COMMIT_SHA = "c".repeat(40);
    private static final String ENVIRONMENT = "nonprod";
    private static final String TERRAFORM_VERSION = "1.6.6";
    private static final String PROVIDER_LOCK_HASH = "sha256:lock-abc";

    private static final class FixedClock extends Clock {
        private final Instant instant;

        FixedClock(Instant instant) {
            this.instant = instant;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }

    /** A minimal test-only {@link RunnerLedgerRepository} whose {@code claim()} always returns a
     * fixed outcome - used to prove {@link ControlledRunner}'s handling of
     * {@link RunnerClaimOutcome#AMBIGUOUS} without needing a real database to provoke it. */
    private static final class FixedOutcomeLedger implements RunnerLedgerRepository {
        private final RunnerClaimOutcome outcome;

        FixedOutcomeLedger(RunnerClaimOutcome outcome) {
            this.outcome = outcome;
        }

        @Override
        public RunnerClaimOutcome claim(RunnerRequest request, Instant claimedAt) {
            return outcome;
        }

        @Override
        public void recordTerminalEvidence(RunnerEvidence evidence) {
            throw new IllegalStateException("must never be called when claim() did not return CLAIMED");
        }

        @Override
        public Optional<RunnerEvidence> findHistoricalEvidence(String runnerRequestId) {
            return Optional.empty();
        }
    }

    /** Marks whether {@code resolve()} was ever called - proves the pipeline never proceeds past
     * the claim step for an AMBIGUOUS outcome. */
    private static final class MarkerArtifactStore implements com.iacagent.iacagent.runner.RunnerArtifactStore {
        final AtomicBoolean resolveCalled = new AtomicBoolean(false);
        private final InMemoryRunnerArtifactStore delegate = new InMemoryRunnerArtifactStore();

        @Override
        public Optional<com.iacagent.iacagent.runner.StoredArtifact> resolve(String artifactId) {
            resolveCalled.set(true);
            return delegate.resolve(artifactId);
        }
    }

    private RunnerRequest baseRequest(String requestId) {
        return new RunnerRequest(requestId, REPOSITORY, COMMIT_SHA, ENVIRONMENT, "artifact-1", "plan-sha",
                TERRAFORM_VERSION, PROVIDER_LOCK_HASH, "approval-1", RunnerOperation.PREPARE_EXECUTION);
    }

    private ControlledRunner runnerWithLedger(Path root, RunnerLedgerRepository ledger, MarkerArtifactStore artifactStore) {
        RunnerIdentity identity = new RunnerIdentity("runner-1", "test-runner", Set.of(ENVIRONMENT), true);
        return new ControlledRunner(
                new StaticRunnerIdentityProvider(identity),
                Set.of("test-runner"),
                new RepositoryBackedApprovalProvider(new InMemoryApprovalRepository()),
                artifactStore,
                new StaticRunnerToolchainContext(TERRAFORM_VERSION, PROVIDER_LOCK_HASH),
                new RunnerWorkspaceManager(root),
                ledger,
                new FixedClock(NOW)
        );
    }

    // ===================== RunnerClaimOutcome.AMBIGUOUS wiring =====================

    @Test
    void ambiguousClaimOutcomeBlocksWithDedicatedReasonCode(@TempDir Path root) {
        MarkerArtifactStore artifactStore = new MarkerArtifactStore();
        ControlledRunner runner = runnerWithLedger(root, new FixedOutcomeLedger(RunnerClaimOutcome.AMBIGUOUS), artifactStore);

        RunnerEvidence evidence = runner.execute(baseRequest("req-ambiguous"));

        assertEquals(RunnerState.BLOCKED, evidence.finalState());
        assertEquals(List.of(RunnerReasonCode.RUNNER_LEDGER_CLAIM_AMBIGUOUS), evidence.reasonCodes());
    }

    @Test
    void ambiguousClaimOutcomeNeverProceedsPastClaimStep(@TempDir Path root) {
        MarkerArtifactStore artifactStore = new MarkerArtifactStore();
        ControlledRunner runner = runnerWithLedger(root, new FixedOutcomeLedger(RunnerClaimOutcome.AMBIGUOUS), artifactStore);

        runner.execute(baseRequest("req-ambiguous-2"));

        assertFalse(artifactStore.resolveCalled.get(), "an ambiguous claim outcome must never let the pipeline reach artifact resolution");
    }

    @Test
    void ambiguousClaimOutcomeIsNeverTreatedAsClaimedOrAsNoClaimExists(@TempDir Path root) {
        // Regression proof for the exact hazard AMBIGUOUS exists to avoid: it must never map to
        // any of the OTHER claim outcomes' reason codes.
        MarkerArtifactStore artifactStore = new MarkerArtifactStore();
        ControlledRunner runner = runnerWithLedger(root, new FixedOutcomeLedger(RunnerClaimOutcome.AMBIGUOUS), artifactStore);

        RunnerEvidence evidence = runner.execute(baseRequest("req-ambiguous-3"));

        assertNotEquals(RunnerState.READY_FOR_FUTURE_EXECUTION, evidence.finalState());
        for (RunnerReasonCode reason : evidence.reasonCodes()) {
            assertNotEquals(RunnerReasonCode.DUPLICATE_RUNNER_REQUEST, reason);
            assertNotEquals(RunnerReasonCode.RUNNER_REQUEST_FINGERPRINT_MISMATCH, reason);
            assertNotEquals(RunnerReasonCode.RUNNER_REQUEST_INCOMPLETE, reason);
        }
    }

    // ===================== RunnerLedgerConfiguration - no silent fallback =====================

    @Test
    void configurationFactoryRejectsMissingMode() {
        var e = assertThrows(RunnerLedgerConfigurationException.class, () -> RunnerLedgerConfiguration.create(Map.of()));
        assertTrue(e.getMessage().contains("runner.ledger.mode"));
    }

    @Test
    void configurationFactoryRejectsNonPostgresMode() {
        assertThrows(RunnerLedgerConfigurationException.class,
                () -> RunnerLedgerConfiguration.create(Map.of("runner.ledger.mode", "h2")));
        assertThrows(RunnerLedgerConfigurationException.class,
                () -> RunnerLedgerConfiguration.create(Map.of("runner.ledger.mode", "in-memory")));
    }

    @Test
    void configurationFactoryNeverReturnsWithoutFullPostgresConfig() {
        // "postgres" mode declared but no other keys present - must fail closed, never construct a
        // partially-configured or default-valued repository.
        assertThrows(RunnerLedgerConfigurationException.class,
                () -> RunnerLedgerConfiguration.create(Map.of("runner.ledger.mode", "postgres")));
    }

    // ===================== PostgresRunnerLedgerConfig validation =====================

    private Map<String, String> validProductionProperties() {
        return Map.ofEntries(
                Map.entry("runner.ledger.mode", "postgres"),
                Map.entry("runner.ledger.postgres.jdbcUrl", "jdbc:postgresql://db.internal:5432/runner"),
                Map.entry("runner.ledger.postgres.username", "runner_app"),
                Map.entry("runner.ledger.postgres.passwordEnvVar", "RUNNER_LEDGER_PG_PASSWORD_TEST_UNSET"),
                Map.entry("runner.ledger.postgres.sslMode", "verify-full"),
                Map.entry("runner.ledger.postgres.minPoolSize", "2"),
                Map.entry("runner.ledger.postgres.maxPoolSize", "10"),
                Map.entry("runner.ledger.postgres.connectionTimeoutMillis", "3000"),
                Map.entry("runner.ledger.postgres.statementTimeoutMillis", "5000"));
    }

    @Test
    void fromPropertiesRequiresEveryKey() {
        Map<String, String> full = validProductionProperties();
        for (String key : full.keySet()) {
            if (key.equals("runner.ledger.mode")) {
                continue;
            }
            var partial = new java.util.HashMap<>(full);
            partial.remove(key);
            assertThrows(RunnerLedgerConfigurationException.class, () -> PostgresRunnerLedgerConfig.fromProperties(partial),
                    "missing " + key + " must fail closed");
        }
    }

    @Test
    void fromPropertiesRejectsNonPostgresqlJdbcUrl() {
        var props = new java.util.HashMap<>(validProductionProperties());
        props.put("runner.ledger.postgres.jdbcUrl", "jdbc:h2:mem:test");
        assertThrows(RunnerLedgerConfigurationException.class, () -> PostgresRunnerLedgerConfig.fromProperties(props));
    }

    @Test
    void fromPropertiesRejectsUnsafeSslModes() {
        for (String unsafe : List.of("disable", "allow", "prefer", "DISABLED_FOR_TESTS_ONLY", "garbage")) {
            var props = new java.util.HashMap<>(validProductionProperties());
            props.put("runner.ledger.postgres.sslMode", unsafe);
            assertThrows(RunnerLedgerConfigurationException.class, () -> PostgresRunnerLedgerConfig.fromProperties(props),
                    "sslMode=" + unsafe + " must never be accepted for production");
        }
    }

    @Test
    void fromPropertiesAcceptsEachProductionSafeSslModeCaseInsensitively() {
        for (String safe : List.of("require", "REQUIRE", "verify-ca", "Verify-Full")) {
            var props = new java.util.HashMap<>(validProductionProperties());
            props.put("runner.ledger.postgres.sslMode", safe);
            PostgresRunnerLedgerConfig config = PostgresRunnerLedgerConfig.fromProperties(props);
            assertTrue(config.tlsMode().isProductionSafe());
        }
    }

    @Test
    void fromPropertiesRejectsInvalidPoolBounds() {
        var zeroMinPool = new java.util.HashMap<>(validProductionProperties());
        zeroMinPool.put("runner.ledger.postgres.minPoolSize", "0");
        assertThrows(RunnerLedgerConfigurationException.class, () -> PostgresRunnerLedgerConfig.fromProperties(zeroMinPool));

        var maxLessThanMin = new java.util.HashMap<>(validProductionProperties());
        maxLessThanMin.put("runner.ledger.postgres.minPoolSize", "10");
        maxLessThanMin.put("runner.ledger.postgres.maxPoolSize", "2");
        assertThrows(RunnerLedgerConfigurationException.class, () -> PostgresRunnerLedgerConfig.fromProperties(maxLessThanMin));

        var unboundedPool = new java.util.HashMap<>(validProductionProperties());
        unboundedPool.put("runner.ledger.postgres.maxPoolSize", "5000");
        assertThrows(RunnerLedgerConfigurationException.class, () -> PostgresRunnerLedgerConfig.fromProperties(unboundedPool));
    }

    @Test
    void fromPropertiesRejectsOutOfBoundsTimeouts() {
        var tooSmall = new java.util.HashMap<>(validProductionProperties());
        tooSmall.put("runner.ledger.postgres.connectionTimeoutMillis", "1");
        assertThrows(RunnerLedgerConfigurationException.class, () -> PostgresRunnerLedgerConfig.fromProperties(tooSmall));

        var tooLarge = new java.util.HashMap<>(validProductionProperties());
        tooLarge.put("runner.ledger.postgres.statementTimeoutMillis", "999999999");
        assertThrows(RunnerLedgerConfigurationException.class, () -> PostgresRunnerLedgerConfig.fromProperties(tooLarge));
    }

    @Test
    void fromPropertiesNeverReadsPasswordValueDirectlyFromProperties() {
        // The password is resolved only via the named environment variable, never from a property
        // map value - a caller cannot smuggle a literal password through configuration properties.
        var props = new java.util.HashMap<>(validProductionProperties());
        props.put("runner.ledger.postgres.password", "should-be-ignored-entirely");
        PostgresRunnerLedgerConfig config = PostgresRunnerLedgerConfig.fromProperties(props);
        assertFalse(config.toString().contains("should-be-ignored-entirely"));
    }

    // ===================== Secret redaction =====================

    @Test
    void forTestsConfigToStringNeverContainsThePassword() {
        String secret = "sUp3r-S3cr3t-Marker-Value";
        PostgresRunnerLedgerConfig config = PostgresRunnerLedgerConfig.forTests("jdbc:postgresql://localhost:5432/x", "app", secret);
        assertFalse(config.toString().contains(secret), "toString() must never contain the credential value");
    }

    @Test
    void productionConfigToStringNeverContainsCredentialEnvVarValue() {
        PostgresRunnerLedgerConfig config = PostgresRunnerLedgerConfig.fromProperties(validProductionProperties());
        String dump = config.toString();
        assertFalse(dump.toLowerCase(java.util.Locale.ROOT).contains("password="), "diagnostic dump must never echo a raw password= value");
    }

    @Test
    void jdbcUrlRedactionStripsEmbeddedPasswordQueryParameter() {
        // Defensive: this class never constructs a URL like this itself, but a hostile/malformed
        // one must still never leak a password through toString().
        assertThrows(RunnerLedgerConfigurationException.class, () ->
                new PostgresRunnerLedgerConfig("not-a-postgres-url?password=leak-me", "u",
                        RunnerLedgerCredentialSource.forTests("x"), RunnerLedgerTlsMode.REQUIRE, 1, 2, 1000, 1000));
        // Also verify redaction on an otherwise-valid URL that happens to carry the query param.
        PostgresRunnerLedgerConfig config = new PostgresRunnerLedgerConfig(
                "jdbc:postgresql://host:5432/db?password=leak-me", "u",
                RunnerLedgerCredentialSource.forTests("x"), RunnerLedgerTlsMode.REQUIRE, 1, 2, 1000, 1000);
        assertFalse(config.toString().contains("leak-me"));
    }

    // ===================== RunnerLedgerCredentialSource =====================

    @Test
    void credentialSourceFromEnvironmentVariableFailsClosedWhenUnset() {
        RunnerLedgerCredentialSource source = RunnerLedgerCredentialSource.fromEnvironmentVariable("RUNNER_LEDGER_PG_PASSWORD_TEST_DEFINITELY_UNSET");
        assertThrows(RunnerLedgerConfigurationException.class, source::password);
    }

    // ===================== RunnerLedgerTlsMode =====================

    @Test
    void tlsModeParseProductionValueNeverReturnsTestOnlyValue() {
        assertThrows(RunnerLedgerConfigurationException.class, () -> RunnerLedgerTlsMode.parseProductionValue("disable"));
        assertThrows(RunnerLedgerConfigurationException.class, () -> RunnerLedgerTlsMode.parseProductionValue("DISABLED_FOR_TESTS_ONLY"));
        assertThrows(RunnerLedgerConfigurationException.class, () -> RunnerLedgerTlsMode.parseProductionValue(null));
    }

    @Test
    void disabledForTestsOnlyIsNeverProductionSafe() {
        assertFalse(RunnerLedgerTlsMode.DISABLED_FOR_TESTS_ONLY.isProductionSafe());
    }

    // ===================== Ambient-environment scan, narrowed to the carve-out itself =====================

    @Test
    void onlyRunnerLedgerCredentialSourceReadsAmbientEnvironmentWithinTheJdbcSubpackage() throws java.io.IOException {
        // Phase2b2Tests#allowlistProcessEnvironmentPolicyNeverReadsAmbientProcessEnvironmentOutsideComments
        // carves the whole runner/jdbc/ subpackage out of its scan for RunnerLedgerCredentialSource's
        // sake. This test keeps that carve-out from silently becoming a loophole for anything else
        // in the subpackage to start reading ambient environment variables unreviewed.
        Path jdbcSourceDir = Path.of("src/main/java/com/iacagent/iacagent/runner/jdbc");
        assertTrue(Files.isDirectory(jdbcSourceDir), jdbcSourceDir + " must exist");
        try (var files = Files.walk(jdbcSourceDir)) {
            for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                String codeOnly = Files.readString(file).replaceAll("(?s)/\\*.*?\\*/", "").replaceAll("(?m)//.*$", "");
                boolean readsEnv = codeOnly.contains("System.getenv(");
                boolean isTheOneAllowedFile = file.getFileName().toString().equals("RunnerLedgerCredentialSource.java");
                if (readsEnv) {
                    assertTrue(isTheOneAllowedFile, file + " reads the ambient environment but is not the reviewed carve-out file");
                }
            }
        }
    }

    // ===================== Structural regression (repeated from earlier phases per authorization) =====================

    @Test
    void terraformOperationSurfaceRemainsExactlySeven() {
        assertEquals(7, ControlledTerraformOperation.values().length);
        // RunnerOperation carries the same 7 Terraform operations plus exactly 3 non-Terraform ones
        // (VERIFY_ARTIFACT, VERIFY_CONTEXT, PREPARE_EXECUTION) - 10 total, unchanged by Phase 2B-6.
        assertEquals(10, RunnerOperation.values().length);
        for (var value : ControlledTerraformOperation.values()) {
            assertNotEquals("TERRAFORM_APPLY", value.name());
            assertNotEquals("TERRAFORM_DESTROY", value.name());
        }
    }

    @Test
    void noApplyDestroyOrStateMutationReasonCodeOrOperationExistsAnywhere() {
        for (RunnerOperation op : RunnerOperation.values()) {
            String name = op.name();
            assertFalse(name.contains("APPLY"), name);
            assertFalse(name.contains("DESTROY"), name);
        }
        for (var op : ControlledTerraformOperation.values()) {
            String name = op.name();
            assertFalse(name.contains("APPLY"), name);
            assertFalse(name.contains("DESTROY"), name);
        }
    }
}
