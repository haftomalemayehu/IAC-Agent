package com.iacagent.iacagent.runner.jdbc;

import com.iacagent.iacagent.runner.RunnerLedgerRepository;

import java.util.Map;

/**
 * The single production wiring entry point for {@link RunnerLedgerRepository}. There is
 * deliberately no branch here that returns an H2/in-memory implementation: {@code runner.ledger.mode}
 * must be exactly {@code "postgres"}, or this throws {@link RunnerLedgerConfigurationException}
 * rather than defaulting to anything. This is what makes "no silent fallback to H2/in-memory
 * persistence" a structural property of this factory, not a documentation promise a future edit
 * could quietly break - an H2-backed ledger can still be constructed directly by test code (see
 * {@code com.iacagent.iacagent.runner.jdbc.JdbcRunnerLedgerRepository#openH2FileBacked}), just never
 * through this method.
 */
public final class RunnerLedgerConfiguration {

    private RunnerLedgerConfiguration() {
    }

    public static RunnerLedgerRepository create(Map<String, String> properties) {
        if (properties == null) {
            throw new RunnerLedgerConfigurationException("properties map is required");
        }
        String mode = properties.get("runner.ledger.mode");
        if (!"postgres".equals(mode)) {
            throw new RunnerLedgerConfigurationException(
                    "runner.ledger.mode must be exactly 'postgres' for production use, got: " + mode
                            + " (H2/in-memory ledgers are test-only and are never returned by this factory)");
        }
        return PostgresRunnerLedgerRepository.forProduction(PostgresRunnerLedgerConfig.fromProperties(properties));
    }
}
