# Phase 2B-6: Production Runner Ledger & Concurrency Hardening

**Status:** Implemented (`com.iacagent.iacagent.runner.jdbc`), local-commit-only per the authorization ("do not push, do not tag, do not start Phase 2B-7"). Targets **Gate B only** - the runner-request/execution ledger's production durability and concurrency guarantees. Does **not** touch, widen, or claim to close Gate A (approval persistence) even though the same PostgreSQL/HikariCP/Flyway pattern could, in principle, be pointed at it later under a separate authorization.

**Terraform capability surface: unchanged.** `TERRAFORM_VERSION`/`TERRAFORM_FMT_CHECK`/`TERRAFORM_SHOW_PLAN_JSON`/`TERRAFORM_INIT`/`TERRAFORM_VALIDATE`/`TERRAFORM_PROVIDERS_SCHEMA`/`TERRAFORM_PLAN` - exactly seven, no `APPLY`, no `DESTROY`. `ControlledTerraformProcess` remains the sole `ProcessBuilder`-constructing class anywhere in `src/main`; there is still no `Runtime.exec` anywhere in this codebase. Phase 2B-6 adds zero Terraform operations and zero process-invocation capability - it hardens the ledger that a future execution-authority phase will eventually depend on.

---

## 1. Threat Model

The runner ledger is the sole source of truth for "has `runnerRequestId` X already been claimed, and by whom." Its job is to make **at most one successful execution claim** possible per execution/request identity, no matter what happens to the process, the network, or the caller in between. The threats this phase specifically defends against:

1. **Concurrent claimants racing on a previously-unseen id** - two or more callers submit the identical (or a colliding) `runnerRequestId` at the same moment. Exactly one may ever win.
2. **A crashed claimant** - a process claims an id, then dies (crash, OOM-kill, forced restart) before recording terminal evidence. The id must remain permanently blocked (`INCOMPLETE_PRIOR_CLAIM`) rather than silently becoming reclaimable - this phase deliberately introduces **no lease, no TTL-based reclaim, no "probably dead" heuristic**. A stuck `CLAIMED` row is a correct, safe outcome requiring human recovery, not a bug to route around.
3. **A network/connection failure with an unknown outcome** - the claim's mutating statement is sent to the database, and the connection breaks before the caller learns whether it committed. This is the ambiguous-commit-outcome case (§4) - the single most novel threat this phase introduces machinery for, because naively treating it as either "claimed" or "not claimed" is unsafe.
4. **A completely unavailable database** - before a claim is even attempted, or during a replay/history lookup. Must never be silently interpreted as "no previous claim exists," since that would let a caller re-execute something the database (once reachable again) would have told it was already claimed or completed.
5. **A calling-discipline bug elsewhere in the pipeline** - e.g. an evidence record for the wrong logical request being passed into `recordTerminalEvidence`. The guarded completion statement (§7) defends against this independently of whatever validation the caller was supposed to have already done.
6. **An operator/attacker with raw SQL access attempting to reopen or rewrite a completed row.** The database schema itself (not just this repository's own SQL) refuses this - see §3's trigger.

Out of scope for this phase, explicitly: Gate A (approval-store productionization), Gate C (workload identity), Gate D (OS/container sandboxing), Gate E (module/provider supply chain), and any lease/heartbeat/reclaim mechanism for a crashed claimant.

## 2. Atomic Claim Algorithm

`PostgresRunnerLedgerRepository#claim` issues exactly one mutating statement:

```sql
INSERT INTO runner_requests (
    request_id, fingerprint,
    repository, commit_sha, environment, plan_artifact_id, plan_sha256,
    terraform_version_expected, provider_lock_hash_expected, approval_id, requested_operation,
    state, claimed_at, created_at, updated_at
) VALUES (?,?, ?,?,?,?,?, ?,?,?,?, 'CLAIMED', ?, now(), now())
ON CONFLICT (request_id) DO NOTHING
```

`request_id`'s primary key is the actual, database-enforced concurrency boundary - `ON CONFLICT (request_id) DO NOTHING` means the database itself decides, atomically, which one of any number of concurrent callers' `INSERT`s actually creates the row; every other caller's statement affects zero rows, with **no exception raised and no read-then-write window** for the decision itself. This is deliberately *not* `SELECT ... if absent ... INSERT` - that shape would have a race window between the read and the write that no amount of application-level care can close without database-side locking, exactly what the authorization prohibited.

If the `INSERT` returns 1 row affected, the outcome is `CLAIMED`. If it returns 0 (a row already existed), a **separate, read-only** `SELECT fingerprint, state FROM runner_requests WHERE request_id = ?` classifies the *already-settled* outcome:

```text
existing fingerprint == request's fingerprint, state == COMPLETED  -> DUPLICATE_SAME_FINGERPRINT
existing fingerprint == request's fingerprint, state == CLAIMED    -> INCOMPLETE_PRIOR_CLAIM
existing fingerprint != request's fingerprint (either state)       -> FINGERPRINT_MISMATCH
```

This classification is read-only and never participates in the claim decision - a benign race in which the row's state changes between the failed `INSERT` and this `SELECT` (e.g. it moves from `CLAIMED` to `COMPLETED` a moment later) can only produce a marginally stale-but-still-safe answer to the *loser* of the race, never corrupt the ledger or grant a second claim.

## 3. Fingerprint - Unchanged, Reused

The fingerprint stored and compared is exactly the Phase 2B-2-accepted `RunnerRequest#fingerprintSha256()`: encoding version + nine semantic request fields (repository, commitSha, environment, planArtifactId, planSha256, terraformVersion, providerLockHash, approvalId, requestedOperation), each 4-byte-big-endian-length-prefixed, UTF-8 encoded, SHA-256'd. `runnerRequestId` itself is excluded from the hash, as before. This phase introduces **no second fingerprint definition** - `PostgresRunnerLedgerRepository#recordTerminalEvidence` recomputes the identical fingerprint from `RunnerEvidence`'s own identity fields (`repository`/`commitSha`/`environment`/`planArtifactId`/`expectedPlanSha256`/`terraformVersionExpected`/`providerLockHashExpected`/`approvalId`/`operation` - the exact nine fields, just named with an Expected/Observed split on the evidence record) by constructing an equivalent `RunnerRequest` and calling the same method. The stored `fingerprint` column is what lets a replay of the same `runnerRequestId` prove whether the presented request is the one originally claimed.

## 4. Ambiguous Commit Outcome - A First-Class Domain Value

`RunnerClaimOutcome` gained a fifth value, `AMBIGUOUS` (see its javadoc for the full reasoning). It exists specifically for this case: the `INSERT ... ON CONFLICT` statement is transmitted to PostgreSQL, but the connection breaks before this caller can read the result - e.g. the server actually committed the row and then the acknowledgment was lost in transit. From the caller's perspective this is neither "definitely claimed" (treating it as such risks a second execution if it actually failed) nor "definitely not claimed" (treating it as such risks a second execution if it actually succeeded, since a naive retry-as-fresh-claim could otherwise coexist with the real row - though this repository's `ON CONFLICT` design makes even that "risk" actually safe by construction, the deeper issue is that returning any OTHER outcome would be an outright fabrication of certainty the code does not have).

`claim()`'s `SQLException` handling distinguishes two cases:

- An exception acquiring the **connection itself** (nothing was ever transmitted) → unambiguous failure → thrown `RunnerLedgerPersistenceException` → the existing `ControlledRunner` catch block already blocks (`RUNNER_LEDGER_UNAVAILABLE`).
- An exception during the **`INSERT`'s own `executeUpdate()` call** (the statement was transmitted) → `RunnerClaimOutcome.AMBIGUOUS`, returned, never thrown.

`ControlledRunner`'s claim-outcome `switch` now maps `AMBIGUOUS` to a new reason code, `RUNNER_LEDGER_CLAIM_AMBIGUOUS`, and blocks - exactly like every other non-`CLAIMED` outcome. **No retry is attempted inside `claim()` itself** - per the authorization's explicit instruction ("the same attempt must not proceed based on inference"). Resolution happens the honest way: a later resubmission of the same `runnerRequestId` calls `claim()` fresh, and the SAME `INSERT ... ON CONFLICT` logic naturally observes whichever outcome the database actually settled on (`CLAIMED` if the ambiguous attempt genuinely never committed; `INCOMPLETE_PRIOR_CLAIM`/`DUPLICATE_SAME_FINGERPRINT` if it did). No special "reconciliation" code path exists or is needed - the same atomic-claim mechanism that makes normal contention safe also makes ambiguity-recovery safe, for free.

Proven with a real PostgreSQL, deterministically, via `Phase2b6PostgresAcceptanceTests#ambiguousCommitOutcomeIsReportedAndAFreshRetryReconciles`/`#ambiguousCommitOutcomeNeverDoubleInsertsOnRetry`, using a `DataSource`-wrapping fault injector (`AckLossFaultInjectingDataSource`) that lets the real `INSERT` execute and commit against the real database, then throws before the result reaches the caller - reproducing "committed but ack lost" deterministically rather than relying on a non-deterministic live network fault.

**Why completion has no equivalent `AMBIGUOUS` outcome.** `recordTerminalEvidence` is `void` and either succeeds or throws `RunnerLedgerPersistenceException`/`IllegalStateException` - deliberately, not by oversight. An ambiguous *completion* cannot cause a double execution the way an ambiguous *claim* could: either the guarded `UPDATE` genuinely committed (a later replay observes `DUPLICATE_SAME_FINGERPRINT` - safe) or it never did (the row stays `CLAIMED` forever, blocking all future attempts as `INCOMPLETE_PRIOR_CLAIM` until a human intervenes - also safe, if inconvenient). `ControlledRunner` already treats any thrown `RunnerLedgerPersistenceException` from `recordTerminalEvidence` as `BLOCKED`, cleans up the workspace, and never hands back an authoritative `READY_FOR_FUTURE_EXECUTION` result - so a plain thrown exception is sufficient here.

## 5. SQL Constraints (`db/migration/runner-postgres/V1__create_runner_requests.sql`)

```text
request_id                  PRIMARY KEY
fingerprint                 NOT NULL
repository/commit_sha/environment/plan_artifact_id/plan_sha256/
terraform_version_expected/provider_lock_hash_expected/approval_id/
requested_operation         NOT NULL (all - the immutable identity fields)
state                       NOT NULL CHECK (state IN ('CLAIMED','COMPLETED'))
claimed_at                  NOT NULL
completed_at                CHECK: NULL iff state='CLAIMED', NOT NULL iff state='COMPLETED'
```

No index beyond the primary key - every query (`claim`, `recordTerminalEvidence`, `findHistoricalEvidence`) looks up by `request_id` alone, already PK-covered; an additional index would be exactly the kind of unjustified addition the authorization warned against.

**Database-enforced transition guard.** A `CHECK` constraint cannot see a row's prior value, so "a `COMPLETED` row is terminal and immutable" and "identity/fingerprint/`claimed_at` never change after claim" can only be made a *database-enforced* fact (not merely an application-code convention) via a `BEFORE UPDATE` trigger:

```sql
CREATE FUNCTION runner_requests_guard_transition() RETURNS trigger AS $$
BEGIN
    IF OLD.state = 'COMPLETED' THEN
        RAISE EXCEPTION '... is COMPLETED and immutable ...' USING ERRCODE = '25000';
    END IF;
    IF <any identity/fingerprint/claimed_at column differs between OLD and NEW> THEN
        RAISE EXCEPTION '... identity/fingerprint/claimed_at fields are immutable after claim ...' USING ERRCODE = '25000';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
```

This is the one piece of schema-level logic beyond the two-state `CLAIMED`/`COMPLETED` model itself - justified because it is the *only* way to make immutability a property the database enforces against **any** SQL statement, not just the two the application ever issues. Proven directly at the raw-SQL level (bypassing the repository class entirely) by `Phase2b6PostgresAcceptanceTests#completedRowCanNeverBeReopenedEvenAtRawSqlLevel`/`#identityFieldsCannotBeRewrittenAfterClaimEvenAtRawSqlLevel`.

**Dialect note.** `terraform_process_evidence`/`terraform_init_evidence`/`terraform_validate_evidence`/`terraform_provider_schema_evidence`/`terraform_plan_evidence` are `JSONB` here (versus `VARCHAR` in the H2 reference schema) - a genuinely justified dialect difference, since the database itself then validates well-formedness at write time. This migration lives at a separate Flyway location (`classpath:db/migration/runner-postgres`, versus `classpath:db/migration/runner` for H2) and is written for a fresh PostgreSQL deployment - it is not a migration-in-place of the H2 schema and never needs to be.

## 6. Transaction / Isolation Model

Every statement in `PostgresRunnerLedgerRepository` runs under the connection pool's default **autocommit** mode at PostgreSQL's default **READ COMMITTED** isolation. There is no multi-statement transaction anywhere in this class - `claim()`'s optional follow-up classification `SELECT` is a deliberately separate, non-atomic-with-the-insert, read-only statement (see §2: it only describes an outcome the database has already settled, so it needs no transactional coupling to the `INSERT`). Correctness rests entirely on:

- the primary key / `ON CONFLICT` semantics for the claim decision, and
- the guarded `UPDATE ... WHERE request_id = ? AND fingerprint = ? AND state = 'CLAIMED'` for completion, and
- the `BEFORE UPDATE` trigger for immutability enforcement,

**never** on isolation level. `SERIALIZABLE` is neither used nor required - this is documented explicitly per the authorization's instruction not to claim a stronger isolation requirement than actually exists. `statement_timeout` (§9) is set per-session via `HikariConfig#connectionInitSql`, bounding every individual statement; there is no separate transaction-timeout configuration because no transaction here ever spans more than one statement.

## 7. Guarded Completion

```sql
UPDATE runner_requests
SET state = 'COMPLETED',
    runner_id = ?, runner_class = ?, runner_environment_scope = ?,
    observed_plan_sha256 = ?, terraform_version_observed = ?, provider_lock_hash_observed = ?,
    approval_validation_result = ?, final_state = ?, reason_codes = ?, completed_at = ?,
    terraform_process_evidence = ?, terraform_init_evidence = ?, terraform_validate_evidence = ?,
    terraform_provider_schema_evidence = ?, terraform_plan_evidence = ?,
    updated_at = now()
WHERE request_id = ? AND fingerprint = ? AND state = 'CLAIMED'
```

`updated != 1` throws `IllegalStateException` - zero rows affected (whether because the id was never claimed, is already `COMPLETED`, or the fingerprint doesn't match what was actually claimed) is **never** silently treated as success. The `fingerprint` predicate is defense-in-depth beyond what the caller's own claim-time check already established: `Phase2b6PostgresAcceptanceTests#fingerprintMismatchInEvidenceCannotCompleteADifferentlyClaimedRow` proves that even when a row genuinely IS in `CLAIMED` state (so the state predicate alone would permit an update), evidence reconstructed from a *different* identity than what was actually claimed under that id is still rejected.

## 8. Restart Durability

Proven with a real, single shared PostgreSQL instance and **two structurally independent `PostgresRunnerLedgerRepository` instances, each backed by its own freshly-constructed `DataSource`/connection** (no shared in-process object of any kind) - `Phase2b6PostgresAcceptanceTests#restartDurabilityIncompleteClaimIsObservedByANewInstance` and `#restartDurabilityCompletedIsObservedByANewInstanceAndDuplicateStaysBlocked`:

```text
instance A claims                              -> CLAIMED
instance A "disappears" (never touched again)
instance B (fresh repository + fresh DataSource) claims the same id -> INCOMPLETE_PRIOR_CLAIM

instance A claims, then records terminal evidence -> COMPLETED
instance B (fresh repository + fresh DataSource) claims the same id -> DUPLICATE_SAME_FINGERPRINT
instance B finds the original evidence via findHistoricalEvidence   -> present
```

`PostgresRunnerLedgerRepository` itself carries zero instance state beyond its `DataSource` reference and observer - there is no cache, no replay map, nothing a "restart" could lose. Durability is entirely the database's property, not this class's.

## 9. Database Outage Behavior

```text
DB unavailable before claim               -> claim() throws RunnerLedgerPersistenceException (connection acquisition itself fails)
DB unavailable during replay lookup       -> findHistoricalEvidence() throws RunnerLedgerPersistenceException, NEVER returns Optional.empty()
connection pool exhausted / stuck server  -> fails closed within the configured connectionTimeoutMillis bound, never hangs indefinitely
```

A database error is never converted into "no previous claim exists" anywhere in this class - every catch block that would otherwise swallow a `SQLException` into an `Optional.empty()`/default value instead rethrows `RunnerLedgerPersistenceException`. Proven against a real (deliberately unreachable) address in `Phase2b6PostgresAcceptanceTests#databaseUnavailableBeforeClaimFailsClosed`/`#databaseUnavailableDuringReplayLookupFailsClosedNeverEmpty`, and against genuine pool exhaustion (a real PostgreSQL instance, a pool bounded to 1 connection, the sole connection deliberately held open by the test) in `#connectionPoolExhaustionFailsClosedWithinABoundedTime`, which asserts the failure surfaces well within the configured bound rather than hanging.

## 10. TLS

`RunnerLedgerTlsMode` maps directly to pgjdbc's `sslmode` connection property. Production configuration (`PostgresRunnerLedgerConfig#fromProperties`, the sole entry point `RunnerLedgerConfiguration#create` uses) accepts **only** `require`, `verify-ca`, or `verify-full` (case-insensitive) via `RunnerLedgerTlsMode#parseProductionValue` - `disable`/`allow`/`prefer`, and even the literal enum constant name `DISABLED_FOR_TESTS_ONLY`, are all rejected with `RunnerLedgerConfigurationException`. The test-only escape hatch (`RunnerLedgerTlsMode.DISABLED_FOR_TESTS_ONLY`, used only by `PostgresRunnerLedgerConfig#forTests`) is structurally unreachable from the string-parsing production path - there is no string value that resolves to it.

This is not just a configuration-level claim: `Phase2b6PostgresAcceptanceTests#productionSslModeRequireRefusesThePlaintextTestContainer` proves the setting has real teeth by requesting `sslmode=require` against the Testcontainers PostgreSQL instance (which has no TLS listener) and confirming the connection attempt genuinely fails - if the TLS knob were silently ignored, this connection would succeed instead.

## 11. Resource Bounds

`PostgresRunnerLedgerConfig`'s compact constructor validates every bound eagerly (construction throws immediately on an invalid value - never a lazy failure at first use):

```text
minPoolSize        >= 1
maxPoolSize        >= minPoolSize, <= 100
connectionTimeoutMillis   250 - 60,000
statementTimeoutMillis    250 - 300,000
```

`connectionTimeoutMillis` becomes HikariCP's `connectionTimeout` (how long a caller waits to acquire a pooled connection before failing closed - proven under real exhaustion, §9). `statementTimeoutMillis` becomes a per-session `SET statement_timeout = <ms>` issued via `HikariConfig#connectionInitSql` on every new physical connection - bounding every individual statement this repository issues, so "a stuck database must fail closed rather than hold execution authority indefinitely" holds at the statement level too.

## 12. Production Configuration - No Silent Fallback

`RunnerLedgerConfiguration#create(Map<String,String> properties)` is the **sole** production wiring entry point. `runner.ledger.mode` must be exactly `"postgres"` - any other value (including absent) throws `RunnerLedgerConfigurationException`. There is **no branch in this factory that returns an H2 or in-memory repository** - this is a structural property (the method's source code has no such branch to fall into), not a runtime check that a future edit could accidentally weaken. An H2-backed ledger remains constructible directly by test code (`JdbcRunnerLedgerRepository#openH2FileBacked`), just never reachable through this factory.

Required keys under `runner.ledger.postgres.`: `jdbcUrl`, `username`, `passwordEnvVar` (the *name* of an environment variable - the password value itself is never read from the properties map, so it can never be smuggled through configuration text), `sslMode`, `minPoolSize`, `maxPoolSize`, `connectionTimeoutMillis`, `statementTimeoutMillis`. Every key is required; a missing or invalid value throws rather than defaulting.

**Secret handling.** `RunnerLedgerCredentialSource` is a supplier abstraction, never a plain field - `RunnerLedgerCredentialSource#fromEnvironmentVariable` re-reads the named environment variable fresh on every call (never cached), and the physical-connection layer (`PostgresRunnerLedgerRepository`'s private `CredentialResolvingDataSource`) calls it again for every NEW connection HikariCP opens, rather than capturing the password once into a HikariCP-internal field. `PostgresRunnerLedgerConfig#toString()` never includes the credential, and defensively redacts any `password=` substring that might appear embedded in a hostile/malformed JDBC URL. Proven against a real authentication failure (`Phase2b6PostgresAcceptanceTests#wrongPasswordAuthFailureNeverLeaksThePasswordInAnyExceptionMessage`) - the full exception cause chain from a genuine wrong-password connection attempt against real PostgreSQL is walked and asserted never to contain the password value.

## 13. Observability

`RunnerLedgerObserver`/`RunnerLedgerEvent`/`RunnerLedgerEventType` provide sanitized structured events for exactly the required set: `CLAIM_SUCCESS`, `DUPLICATE`, `FINGERPRINT_MISMATCH`, `INCOMPLETE_PRIOR_CLAIM`, `COMPLETION`, `DATABASE_UNAVAILABLE`, `AMBIGUOUS_RESULT`. An event carries only its type, the (non-secret) `runnerRequestId`, and a timestamp - there is no field for a database password, connection secret, or raw SQL parameter, so a compliant observer cannot leak one regardless of what it does with the event. `Slf4jRunnerLedgerObserver` (the production-appropriate implementation `PostgresRunnerLedgerRepository#forProduction` uses by default) logs at INFO/WARN/ERROR by severity; `NoOpRunnerLedgerObserver` (the default when unspecified) discards everything.

## 14. Evidence Immutability

- **First evidence remains authoritative.** `Phase2b6PostgresAcceptanceTests#firstEvidenceRemainsAuthoritativeAndDuplicateReplayCannotReplaceIt` claims, completes, then replays the identical request and confirms `claim()` reports `DUPLICATE_SAME_FINGERPRINT` (never re-executing) while `findHistoricalEvidence` still returns the original evidence.
- **Duplicate/fingerprint-mismatch replay cannot replace it.** No code path in `PostgresRunnerLedgerRepository` ever calls the guarded `UPDATE` for an id whose `claim()` did not return `CLAIMED` to that exact caller; §7 additionally proves the guard itself would reject a mismatched attempt even if one were made.
- **A completed request cannot be reopened** - enforced twice over: the guarded `UPDATE`'s `state = 'CLAIMED'` predicate (application layer, §7) and the `BEFORE UPDATE` trigger (database layer, §5) both independently refuse any further write to a `COMPLETED` row.

## 15. PostgreSQL Acceptance Procedure - and Its Actual Result

The full acceptance suite:

- `src/postgresTest/java/.../Phase2b6PostgresAcceptanceTests.java` - connectivity/contention (2/10/50-way)/restart/outage/ambiguous-commit (including a full `ControlledRunner` end-to-end proof)/completion-guard/immutability/evidence-immutability/TLS-enforcement/secret-redaction.
- `src/postgresTest/java/.../Phase2b6MigrationAcceptanceTests.java` - empty-database migration, idempotent restart-at-latest, Flyway checksum validation, incompatible-schema fail-closed behavior.
- `PostgresTestTarget` - resolves the target PostgreSQL instance either from a Testcontainers-managed container (the default, portable path for any standard CI with a working Docker daemon) or from an external, already-running instance via `-Dpgtest.jdbcUrl`/`-Dpgtest.username`/`-Dpgtest.password` system properties. No test assertion or ledger-code behavior differs between the two modes - only how connection info is obtained.
- A dedicated Gradle source set + task (`./gradlew postgresTest`), deliberately never part of `check`/`test`.

**Why the external-target mode exists.** In this development sandbox, Testcontainers' bundled `docker-java` HTTP client could not obtain a valid daemon handle through the local Docker Desktop socket (every provider strategy received an anomalous HTTP 400 response with a mostly-empty body, while a plain `curl` against the identical socket/endpoint returned full, valid daemon info) - reproduced identically across Testcontainers 1.20.4 and 1.21.3, independent of `DOCKER_HOST`, a `~/.testcontainers.properties` override, and `DOCKER_API_VERSION` pinning. Docker itself was fully functional (`docker run`/`docker exec`/`docker rm` all worked normally). Rather than leave the suite unrun, a real `postgres:16-alpine` container was started directly via the `docker` CLI, and the suite was pointed at it via `-Dpgtest.*` - exercising the exact same `PostgresRunnerLedgerRepository`/schema/trigger code against a genuine, independently-running PostgreSQL server, with Testcontainers' Java API taken out of the loop entirely (it never touched the database in this run; it was only unable to programmatically start/stop the container).

**A real defect was found and fixed this way.** The first run failed every test with `FlywayException: Unsupported Database: PostgreSQL 16.15` - `flyway-core` alone (as declared before this fix) does not bundle PostgreSQL dialect support in Flyway 12.x; the H2 reference ledger never needed a dialect module and this gap was invisible until an actual PostgreSQL connection was attempted. **This would have broken `PostgresRunnerLedgerRepository#migrate` in any real production deployment**, not just this sandbox. Fixed by adding `org.flywaydb:flyway-database-postgresql` to `build.gradle`. After that one fix, the full suite passed cleanly on the first subsequent run and again on an independent fresh rerun.

**Actual result: 24/24 tests passed (5 migration + 19 acceptance), 0 failures, 0 errors, reproduced across two independent runs**, against PostgreSQL 16.15 (`postgres:16-alpine`), confirmed via `SELECT version()`:

```text
PostgreSQL 16.15 on aarch64-unknown-linux-musl, compiled by gcc (Alpine 15.2.0) 15.2.0, 64-bit
```

Concrete contention results captured from the actual test runs (two independent executions):

```text
Run A: 2-way  -> CLAIMED=1, INCOMPLETE_PRIOR_CLAIM=1,  AMBIGUOUS=0
Run A: 10-way -> CLAIMED=1, INCOMPLETE_PRIOR_CLAIM=9,  AMBIGUOUS=0
Run A: 50-way -> CLAIMED=1, INCOMPLETE_PRIOR_CLAIM=49, AMBIGUOUS=0
Run A: fingerprint-conflict -> a=FINGERPRINT_MISMATCH, b=CLAIMED
Run A: ambiguous-commit     -> firstAttempt=AMBIGUOUS, retry=INCOMPLETE_PRIOR_CLAIM
Run A: ambiguous end-to-end -> ControlledRunner finalState=BLOCKED, reasonCodes=[RUNNER_LEDGER_CLAIM_AMBIGUOUS]

Run B (independent fresh rerun): 2-way  -> CLAIMED=1, INCOMPLETE_PRIOR_CLAIM=1,  AMBIGUOUS=0
Run B: 10-way -> CLAIMED=1, INCOMPLETE_PRIOR_CLAIM=9,  AMBIGUOUS=0
Run B: 50-way -> CLAIMED=1, INCOMPLETE_PRIOR_CLAIM=49, AMBIGUOUS=0
Run B: fingerprint-conflict -> a=CLAIMED, b=FINGERPRINT_MISMATCH (which side wins is expectedly
                                nondeterministic; the INVARIANT - exactly one winner, exactly one
                                mismatch - held in both runs)
```

The end-to-end ambiguous-outcome test (`ambiguousCommitOutcomeStopsTheControlledRunnerPipelineEntirely`) proves the specific nuance flagged during review: the invocation that receives `AMBIGUOUS` stops at the claim step and never reaches artifact resolution or any later pipeline stage within that same attempt - `ControlledRunner#execute` returns `BLOCKED`/`RUNNER_LEDGER_CLAIM_AMBIGUOUS` and the test's marker artifact store's `resolve()` is asserted never called. Reconciliation happens only via a **separate, later** `claim()` call (the `firstAttempt`/`retry` test above), never inside the ambiguous attempt itself.

**Gate B: CLOSED** on this evidence - see §16.

## 16. Gate B Acceptance Checklist

```text
[x] real PostgreSQL implementation                     - PostgresRunnerLedgerRepository
[x] no H2/in-memory production fallback                - RunnerLedgerConfiguration has no such branch
[x] Flyway PostgreSQL migration                        - db/migration/runner-postgres, separate from H2's
                                                           (requires flyway-database-postgresql - see §15)
[x] database-enforced atomic claim                      - INSERT ... ON CONFLICT (request_id) DO NOTHING
[x] guarded completion                                  - UPDATE ... WHERE request_id/fingerprint/state='CLAIMED'
[x] immutable fingerprint/identity                      - NOT NULL columns + BEFORE UPDATE trigger
[x] multi-instance concurrency proven                   - real PostgreSQL, independent DataSource per caller
[x] 50-way contention proven                            - real PostgreSQL: CLAIMED=1, INCOMPLETE_PRIOR_CLAIM=49
[x] restart durability proven                           - real PostgreSQL, independent repository+DataSource instances
[x] incomplete CLAIMED remains consumed                 - real PostgreSQL, restart durability tests
[x] completed request cannot reopen                     - real PostgreSQL, guarded UPDATE + raw-SQL trigger proof
[x] fingerprint mismatch cannot overwrite                - real PostgreSQL, concurrent + defense-in-depth tests
[x] DB unavailable fails closed                         - real PostgreSQL host, unreachable-address + pool-exhaustion tests
[x] ambiguous commit outcome represented                - real PostgreSQL, fault-injected ack-loss + full
                                                           ControlledRunner end-to-end stop-at-claim proof
[x] TLS production posture                              - real PostgreSQL (no TLS listener): sslmode=require
                                                           genuinely refuses the connection
[x] bounded DB resources/timeouts                       - validated eagerly at config construction; pool
                                                           exhaustion proven to fail closed within bound
[x] secret-redaction tests                              - unit-tested + real wrong-password auth failure
                                                           against real PostgreSQL never leaks the password
[x] actual production isolation level documented/tested - §6, autocommit/READ COMMITTED, no SERIALIZABLE claim
[x] all integration tests run against real PostgreSQL   - 24/24 passed, 0 failures, two independent runs
                                                           (PostgreSQL 16.15, confirmed via SELECT version())

GATE B: CLOSED.
```

## 17. Gates A/C/D/E/F - Unchanged

```text
Gate A: Approval persistence needs real PostgreSQL integration + concurrency verification. Still
open - untouched by this phase (explicitly out of scope per the authorization).
Gate C: Runner identity needs real workload identity/OIDC, not local/reference file attestation.
Still open.
Gate D: Production runner sandboxing - OS/container isolation, resource limits, network policy.
Still open.
Gate E: Module/provider supply-chain governance. Still open.
Gate F: Production remote-state/backend hardening + plan-artifact-at-rest security (Phase 2B-5).
Still open.
```

## 18. No APPLY/DESTROY/State Mutation - Structural Confirmation

Unchanged from every prior phase: `ControlledTerraformOperation`/`RunnerOperation` still have no `APPLY`/`DESTROY` value; `TerraformCommandFactory` is untouched by this phase; there is no generic `execute(List<String>)`/`run(String...)` anywhere in `src/main`; `ControlledTerraformProcess` remains the sole `ProcessBuilder`-constructing class. This phase's entire diff is the runner ledger's persistence layer - it has no code path that could construct or dispatch a Terraform mutation command even in principle.
