# Phase 2B-2: Runner Identity, Durable Request/Evidence Ledger, and Isolation Hardening

**Status:** Implemented (`com.iacagent.iacagent.runner`, `com.iacagent.iacagent.runner.jdbc`). Still zero Terraform execution, zero infrastructure mutation, zero shell/process invocation anywhere in this phase — Phase 2B-1's no-mutation boundary is unchanged and re-verified (§13).

**Upstream binding references:** `docs/phase-2b1-controlled-runner.md` (this phase hardens, not replaces, that design), `docs/roadmap-phase-2.md`, `docs/phase-2a-execution-contract.md`, `docs/phase-2a-threat-model.md`. Phase 2C-1/2C-2 approval contracts (`ApprovalProvider`, `ApprovalValidator`, `ExecutionIdentity`, `ApprovalPersistenceException`) are consumed unchanged.

**What this phase answers, and what it deliberately does not:**

```text
Answers:
  Does replay protection survive a restart?      -> yes: RunnerLedgerRepository, durable, PK-uniqueness-as-atomic-claim
  Can a crashed-but-claimed request be replayed?  -> no: it blocks as RUNNER_REQUEST_INCOMPLETE, forever, until a human resolves it
  Can a caller influence its own runner identity? -> no: RunnerIdentityProvider takes no request parameter at all
  What happens if identity cannot be resolved?    -> BLOCKED / RUNNER_IDENTITY_UNAVAILABLE, never a default/anonymous identity
  Is workspace isolation symlink-resistant?        -> yes: real-path (Files#toRealPath) checks, not just normalize()/startsWith()
  What would a future process's environment look? -> ProcessEnvironment/ProcessEnvironmentPolicy: built up from empty, never filtered down from System.getenv()

Does NOT answer:
  Real cloud workload identity/OIDC               -> HostAttestedRunnerIdentityProvider is local attestation only; Gate C below
  Production-grade durable backend                -> H2 is the reference/acceptance backend; Gate B below
  Any process actually launched                    -> ProcessEnvironmentPolicy is not wired into ControlledRunner; still zero execution capability
```

---

## 1. Durable Runner Request/Evidence Ledger

`RunnerLedgerRepository` (interface, 3 methods: `claim`, `recordTerminalEvidence`, `findHistoricalEvidence`) replaces Phase 2B-1's process-local `ConcurrentHashMap`-backed replay/evidence tracking inside `ControlledRunner`. `ControlledRunner` now holds no state of its own about which ids have been seen — that truth lives exclusively in the injected `RunnerLedgerRepository`, consistent with the architecture discipline that this package's orchestrator manufactures no truth it should instead be consulting (§ preamble of `ControlledRunner`'s own class javadoc).

Two implementations exist:
- `InMemoryRunnerLedgerRepository` — a single `synchronized` lock guarding one `HashMap`, for domain-level unit tests only (`Phase2b2Tests`). Never claimed to be durable.
- `JdbcRunnerLedgerRepository` — plain JDBC (no ORM, no DI wiring), H2 file-backed with `MODE=PostgreSQL`, Flyway-versioned schema at `classpath:db/migration/runner`, the Phase 2B-2 reference/acceptance backend (`Phase2b2JdbcTests`, `com.iacagent.iacagent.runner.jdbc`).

### Schema (`runner_requests`, `V1__create_runner_requests.sql`)

```
runner_request_id            VARCHAR PRIMARY KEY
request_fingerprint          VARCHAR NOT NULL
repository, commit_sha, environment, plan_artifact_id, plan_sha256,
terraform_version_expected, provider_lock_hash_expected, approval_id,
requested_operation                                        VARCHAR NOT NULL (all)
claim_state                  VARCHAR NOT NULL  CHECK IN ('CLAIMED', 'COMPLETED')
runner_id, runner_class, runner_environment_scope          VARCHAR (nullable until COMPLETED)
observed_plan_sha256, terraform_version_observed,
provider_lock_hash_observed, approval_validation_result     VARCHAR (nullable until COMPLETED)
final_state, reason_codes                                   VARCHAR (nullable until COMPLETED)
started_at                   TIMESTAMPTZ NOT NULL
completed_at                 TIMESTAMPTZ (nullable until COMPLETED)
version                      BIGINT NOT NULL DEFAULT 0
created_at, updated_at        TIMESTAMPTZ NOT NULL
```

No indexes beyond the primary key: every lookup (`claim`, `recordTerminalEvidence`, `findHistoricalEvidence`) is by `runner_request_id` alone, already PK-covered. `runner_environment_scope` and `reason_codes` are stored as comma-joined strings (mirroring how `RunnerEvidence` itself models them as `Set<String>`/`List<RunnerReasonCode>`), not a normalized child table — acceptable for a reference backend, revisited if a production backend's query needs justify it.

## 2. Atomic Claim Semantics

`RunnerLedgerRepository.claim(RunnerRequest, Instant) -> RunnerClaimOutcome`. Four outcomes, deliberately fewer than the five the originating prompt sketched:

```java
enum RunnerClaimOutcome { CLAIMED, DUPLICATE_SAME_FINGERPRINT, FINGERPRINT_MISMATCH, INCOMPLETE_PRIOR_CLAIM }
```

- **`ALREADY_COMPLETED` was folded away**: a completed row is now distinguished purely by fingerprint match (`DUPLICATE_SAME_FINGERPRINT`) vs. mismatch (`FINGERPRINT_MISMATCH`) — there was never a case where "already completed" needed to be reported independently of whether the resubmission's content matched.
- **`STORAGE_FAILURE` was folded away**: a genuine infrastructure failure is signaled by throwing `RunnerLedgerPersistenceException` instead (mirrors `ApprovalPersistenceException`'s own convention) — an exception can't be silently missed the way a `default` switch branch could, and it keeps "infra failure" a different *kind* of thing than a legitimate domain outcome.
- **`INCOMPLETE_PRIOR_CLAIM` deliberately collapses two distinct real-world causes** — a genuinely concurrent claim in progress right now, and a prior process that crashed after claiming but before recording terminal evidence — because both look byte-for-byte identical in persisted state (a `CLAIMED` row, no terminal evidence) and both call for the identical response: block, do not proceed, do not guess.

**JDBC implementation of the atomic claim:** a plain `INSERT` into `runner_requests`, with the primary key on `runner_request_id` as the sole atomicity primitive — exactly as `JdbcApprovalRepository.create()` relies on its own primary key for duplicate-id detection. Exactly one concurrent `INSERT` for a given id can ever succeed, guaranteed by the database regardless of how many callers race; there is no read-then-write window for the claim decision itself. On a primary-key violation (SQLSTATE `23505`), a separate, non-transactional `SELECT` classifies the existing row (fingerprint match + `COMPLETED` → duplicate; fingerprint match + `CLAIMED` → incomplete prior claim; fingerprint mismatch → mismatch) purely to inform the *loser* of the race — it writes nothing, so a benign staleness in that classification (the row's state changing between the failed insert and this read) cannot corrupt the ledger, only occasionally report a marginally stale-but-still-safe reason.

`Phase2b2JdbcTests#concurrentClaimsOnTheSameIdHaveExactlyOneWinnerAgainstTheDurableBackend` proves this with 8 real threads racing genuine JDBC transactions against one H2 file, not a synchronized test double. `Phase2b2Tests#claimIsExclusiveAcrossConcurrentCallersForPreviouslyUnseenId` proves the equivalent domain-level property against `InMemoryRunnerLedgerRepository`.

**Fingerprint encoding (revised during review):** `RunnerRequest.fingerprintSha256()` hashes a version-prefixed, **length-prefixed** encoding of every field except `runnerRequestId` itself — each field is preceded by its own 4-byte big-endian byte-length before its UTF-8 bytes, and a 4-byte encoding-version integer precedes the whole thing. The first implementation instead joined fields with a single NUL character as a delimiter. That was found to be unsafe during review: `runnerRequestId + fingerprint` is a security/authorization invariant (it is what distinguishes a genuine resubmission from a different request attempting to reuse the same id), and delimiter-based joining over untrusted, variable-length fields is ambiguous whenever a field can itself contain the delimiter — which a Java `String` can, for a single NUL byte, trivially. Concretely, `repository="a", commitSha="b\0c"` and `repository="a\0b", commitSha="c"` (with every other field identical) produce byte-for-byte the same NUL-joined string, and therefore the same hash, despite being two distinct field tuples — a cryptographic hash cannot repair ambiguity that already exists in the bytes handed to it. Length-prefixing removes the ambiguity structurally: two field tuples can only encode to the same bytes by having every field, including every length prefix, identical. `Phase2b2Tests#differentlyPartitionedFieldsThatWouldCollideUnderNulDelimitedJoiningProduceDifferentFingerprints` reproduces the exact adversarial pair above, confirms it really would have collided under naive NUL-joining (so the test is provably exercising the real gap, not an imagined one), and asserts the shipped encoding does not collide; a companion test does the same for comma/pipe/newline as the more "obvious" delimiter choices a reviewer might otherwise reach for.

## 3. Crash / In-Flight Semantics

A request that was claimed but never reached `recordTerminalEvidence` — because the process crashed, was killed, or lost its database connection mid-pipeline — leaves a row in `CLAIMED` state forever, by design. There is no timeout, no lease expiry, and no automatic reclaim: `claim()` on that same id, from any process, at any later time, returns `INCOMPLETE_PRIOR_CLAIM`, which `ControlledRunner` maps to `BLOCKED` / `RUNNER_REQUEST_INCOMPLETE`. Retrying the same id automatically is never attempted anywhere in this codebase.

This is intentionally conservative: automatically reclaiming a stale `CLAIMED` row would require guessing whether the original claimant is truly dead (not just slow), and a wrong guess in this domain — treating a request as available for re-processing while the original attempt might still be running — is worse than requiring a human to look at it. `Phase2b2JdbcTests#claimedButIncompleteRequestRemainsConsumedAfterRestart` proves this survives an actual process restart (a fresh `JdbcRunnerLedgerRepository` reopening the same H2 file after the first instance's `close()`), not just an in-memory scenario.

## 4. Restart Behavior

Every persisted fact the ledger owns — claim state, request fingerprint, and (once `COMPLETED`) the full terminal evidence — is read back correctly by a **new** `JdbcRunnerLedgerRepository` object opened against the same on-disk H2 file, after the original object's connection pool has been fully disposed (`Phase2b2JdbcTests#completedEvidenceAndHistoricalLookupSurviveRestart`, `#fingerprintMismatchAfterRestartStillBlocks`, `#claimedButIncompleteRequestRemainsConsumedAfterRestart`). A resubmission of a completed id after restart still returns `DUPLICATE_SAME_FINGERPRINT`/`FINGERPRINT_MISMATCH` as appropriate — restart changes nothing about the blocking decision.

## 5. Identity Trust Source

`RunnerIdentityProvider.currentIdentity()` now returns `Optional<RunnerIdentity>` (changed from a bare `RunnerIdentity` in Phase 2B-1) specifically so identity-resolution failure is a first-class, distinguishable outcome (`RUNNER_IDENTITY_UNAVAILABLE`) rather than an NPE or a silent default/anonymous identity. `ControlledRunner` treats both an empty `Optional` and a thrown `RuntimeException` from the provider identically — both block with `RUNNER_IDENTITY_UNAVAILABLE`.

Two implementations:
- `StaticRunnerIdentityProvider` — a fixed identity supplied once at construction; explicitly documented as test/dev use only.
- `HostAttestedRunnerIdentityProvider` — a **local/reference attestation source**, explicitly NOT called "the production path" (revised during review — see below). Reads a JSON file at a `Path` **fixed at construction time** by trusted bootstrap code (an operator, an orchestrator, a host-level provisioning step) — never a `RunnerRequest` field, and structurally never influenced by one, since `currentIdentity()` takes zero parameters (`Phase2b2Tests#requestContentCannotInfluenceResolvedIdentity` asserts this both behaviorally, by resolving identity against two requests whose every field differs and getting an identical result, and structurally, via `RunnerIdentityProvider.class.getDeclaredMethods()[0].getParameterCount() == 0`).

**Request independence is not host attestation (found during review, hardened across two rounds):** the original implementation proved only that a *request* cannot choose or influence the identity file — it did not establish *who* can write to that file, or where that file's path can actually, physically resolve. A plain local JSON file is only as trustworthy as whatever local principal (repository code, the runner process account, workspace content, an attacker with filesystem access) can modify it or redirect it to; proving request-independence alone would let a local file's mutable content be laundered into "runner identity truth" without ever meeting the accepted invariant that identity truth comes from a trusted host/runtime boundary. The class was hardened twice, and reclassified in its own javadoc as a local/reference provider rather than a production one, rather than papering over the gap:

- **Round 1** added a single `excludedWorkspaceRoot` exclusion and a leaf-level symlink check (`Files.isRegularFile(path, NOFOLLOW_LINKS)`). Review found this insufficient: it stopped a workspace or a *direct* symlink substitution from supplying identity, but not a symlink planted in an **ancestor** directory component — a trusted-looking `/opt/iac-agent/identity/runner.json` where `/opt/iac-agent/identity` itself has been replaced by a symlink into a repository-controlled directory defeats a leaf-only check, since `runner.json` itself is a perfectly ordinary regular file. It also had no explicit concept of a repository-checkout root distinct from the workspace root.
- **Round 2 (current)** replaces the single exclusion with an explicit **`trustedIdentityRoot` + `untrustedRoots`** constructor shape:
  - `trustedIdentityRoot` is resolved to its real path (`Path#toRealPath`) **once, at construction**, by the trusted bootstrap code that calls the constructor.
  - Each entry in `untrustedRoots` (expected to include at minimum the runner's own workspace root and any repository-checkout root) is similarly resolved once at construction (best-effort: falls back to a nearest-existing-ancestor real-path walk if the root does not exist yet — see below). Construction fails if `trustedIdentityRoot` itself would resolve underneath any untrusted root (a direct contradiction), though an untrusted root is explicitly allowed to nest *inside* the trusted root (a legitimate "trusted install directory that also contains subdirectories we still don't trust for identity" shape).
  - `identityFile` must, at construction, resolve under `trustedIdentityRoot`.
  - On **every** `currentIdentity()` call (still no caching): the leaf path is rejected outright if it is itself a symlink (`Files.isSymbolicLink`), independent of where it points — this is Round 1's check, kept because "this exact path must not be a symlink" is part of the invariant on its own, not merely a proxy for "does it point somewhere bad." Then `identityFile` is resolved to its **current** real path (`toRealPath`, re-resolved fresh on every call) and that real path must fall under the construction-time trusted root and under none of the untrusted roots — this is what catches ancestor-directory symlink substitution introduced *after* construction, since the real path of a file reached through a since-redirected ancestor directory changes to reflect the redirection even though `identityFile`'s own path string, and its own leaf symlink-ness, never changed.
  - The final resolved file must still be a regular, readable file.
- **A macOS-specific correctness bug surfaced by this hardening, fixed along the way**: comparing a `toRealPath()`-resolved root against a merely `toAbsolutePath().normalize()`-d (non-real) leaf path is unsafe on any platform where part of the path is itself a symlink at the OS level (macOS's `/var` → `/private/var` is exactly this) — two paths that are the same actual location can textually disagree on their prefix. Fixed by resolving every comparison side the same way: real path where the path exists, otherwise a walk up to the nearest existing ancestor, real-path that ancestor, and re-append the not-yet-existing suffix textually.
- **Any failure collapses to `Optional.empty()`**, never a partial or default identity: file missing, not a regular file, unreadable, malformed JSON, a required field (`runnerId`, `runnerClass`) absent, or a path that resolves outside the trusted root/inside an untrusted root — all of it. There is no code path that produces a half-populated `RunnerIdentity`.

Test coverage in `Phase2b2Tests` for this section: `constructorRejectsAnIdentityFileNotUnderTheTrustedIdentityRoot`, `constructorRejectsATrustedRootThatResolvesUnderAnUntrustedRoot`, `identityUnderARepositoryCheckoutRootIsRejected`, `identityUnderTheWorkspaceRootIsRejected`, `safeRegularIdentityFileBelowTrustedRootSucceeds`, `symlinkAtTheIdentityFilePathIsRejectedRatherThanFollowed`, `ancestorDirectorySymlinkRedirectionIntoAnUntrustedRootIsRejected`, `ancestorDirectoryReplacedWithASymlinkAfterAValidFirstReadBlocksOnTheNextRead`, `replacingTheIdentityFileWithASymlinkProducesBlockedRatherThanCachedTrust`, `hostAttestedIdentityProviderReflectsFileChangesOnTheNextCallWithoutCaching`, `requestContentCannotInfluenceResolvedIdentity`.

**What is still explicitly NOT attempted**, and is not claimed: verifying filesystem ownership or POSIX permissions of the identity file, and any cryptographic signature/measurement over the file's content — neither can be done reliably/portably within this phase's scope, and the class's own javadoc says so rather than implying a stronger guarantee than it provides. This remains a **local/reference attestation mechanism**, not real cloud workload identity/OIDC — Gate C is unchanged and still open.

## 6. Workspace/Artifact Isolation

`RunnerWorkspaceManager` retains Phase 2B-1's hash-derived, content-addressed naming (§6 of the 2B-1 doc) and adds:

- **Symlink resistance**: after `createWorkspace` creates a directory (or `stageArtifact` writes a file), the class resolves the **real** path (`Path#toRealPath`, which follows symlinks) and re-verifies it still falls under the root's real path. A plain `normalize()`/`startsWith()` check — which both methods still also do, at path-computation time, as a first line of defense — does not by itself detect a symlink planted at a path component that would cause the OS to actually resolve outside the root at open/write time. `Phase2b2Tests#symlinkPlantedUnderRootIsRejectedRatherThanFollowedOutsideRoot` plants a symlink at the exact hash-derived path a workspace would occupy, pointing outside root, and confirms `createWorkspace` rejects it (throws, rather than silently writing through the symlink) and nothing is ever written to the outside target.
- **Explicit `cleanup(Path)`**: best-effort recursive removal of exactly one workspace, re-verifying the real path falls under root before deleting anything (so it can never be used to remove an arbitrary directory — `Phase2b2Tests#cleanupRejectsAPathOutsideTheConfiguredRoot` proves an out-of-root path is refused, returning `false`, with the target left untouched). Individual file-deletion failures are swallowed (best-effort); the method's boolean return communicates overall success.
- **No caller-supplied filename anywhere**: `stageArtifact(Path workspace, String sha256Hex, byte[] content)` has no `artifactId`/filename parameter at all — the staged filename is derived purely from the (independently recomputed) content hash. `Phase2b2Tests#stageArtifactAcceptsNoCallerSuppliedFilenameOrArtifactIdParameter` pins this signature.

## 7. Cleanup Model

`ControlledRunner.execute()` calls `workspaceManager.cleanup(workspace)` **strictly after** `ledger.recordTerminalEvidence(...)` has succeeded — never before, and on both the success path and the "ledger rejected the write" path (in the latter case, cleanup still runs, since there is no reason to keep the workspace once the outcome has already been forced to `BLOCKED`/`RUNNER_LEDGER_UNAVAILABLE`). A cleanup failure is swallowed (`cleanupQuietly`) and never rewrites an already-persisted verification result — the durable evidence is authoritative regardless of whether its workspace could later be removed.

This is a genuine behavior change from Phase 2B-1, where workspaces (and their staged artifacts) persisted on disk after `execute()` returned. `Phase2b1Tests#concurrentRequestsUseIsolatedWorkspaces` was updated accordingly: it now asserts isolation via each request's own `observedPlanSha256` in its evidence, plus confirms both workspaces are gone from disk afterward (proving cleanup ran for both, with no cross-request interference), rather than inspecting on-disk file contents post-execution. The filesystem-level isolation guarantee itself (separate directories, no cross-contamination of staged bytes) moved to `Phase2b1Tests#workspaceManagerKeepsConcurrentRequestsIsolatedBeforeCleanup`, which exercises `RunnerWorkspaceManager` directly, bypassing `ControlledRunner`'s cleanup, specifically so the assertion isn't racing against the very cleanup behavior this phase introduced.

Since there is still no Terraform execution anywhere in this phase, cleaning up immediately after evidence is durably recorded carries no risk of destroying something a later step would have needed.

## 8. Bounded Process-Environment Contract

No process is launched in Phase 2B-2. `ProcessEnvironment` (a record wrapping an immutable `Map<String, String>`) and `ProcessEnvironmentPolicy` (`buildFor(RunnerRequest, Path) -> ProcessEnvironment`) exist purely to make the future contract explicit and independently testable before any process-invocation code exists to consume it — `ControlledRunner`'s constructor has no dependency on either type (`Phase2b2Tests#controlledRunnerHasNoDependencyOnAnyProcessEnvironmentPolicy` confirms this by inspecting its constructor's parameter types).

`AllowlistProcessEnvironmentPolicy` is the reference implementation: it builds a `LinkedHashMap` starting from **nothing** and adds exactly four entries (`TF_IN_AUTOMATION=true`, `TF_INPUT=0`, `HOME=<workspace>/home`, `TMPDIR=<workspace>/tmp`) — never `PATH`, never anything derived from `System.getenv()`. The contract is enforced two ways:

1. **Behaviorally**: `Phase2b2Tests#allowlistPolicyBuildsOnlyTheFixedExplicitEntrySet` asserts the exact key set; `#requestContentCannotInjectOrChangeAnyEnvironmentVariable` builds the environment from two requests whose every field differs (one deliberately containing `PATH=/evil:$PATH`- and `AWS_ACCESS_KEY_ID=hijacked`-shaped values) against the same workspace and asserts byte-for-byte identical output — request content has zero influence over the result.
2. **Structurally**: `Phase2b2Tests#allowlistProcessEnvironmentPolicyNeverReadsAmbientProcessEnvironmentOutsideComments` source-scans the whole `runner` package for the literal `System.getenv(`, after stripping Java comments first — two of this phase's own javadoc blocks describe the build-up-from-empty contract using the literal text `System.getenv()` in prose, which would otherwise be a false positive; this is the exact "literal strings in comments/tests" lesson learned during Phase 2B-1 (see `docs/phase-2b1-controlled-runner.md`'s own equivalent scan), applied here for a different literal.

The difference between "filter down `System.getenv()`" and "build up from empty" matters structurally, not just stylistically: a filter-down approach silently propagates whatever the host process happens to have, including anything a future host environment change adds without this code changing at all; a build-up-from-empty approach can only ever contain what this code explicitly wrote, which is a property a reviewer can verify by reading `AllowlistProcessEnvironmentPolicy` alone, with no knowledge of the deployment environment.

## 9. Executable/PATH Ownership (Deferred)

No executable path, `PATH` value, or process-invocation code exists anywhere in this phase (§13 confirms via source scan). When a future phase does invoke a process, the working assumption recorded here is that the executable path must be runner-controlled and explicit, never inherited or caller-influenced — `AllowlistProcessEnvironmentPolicy` deliberately omits `PATH` entirely rather than defaulting it "just in case," so that whichever future component first needs an executable path is forced to add it deliberately rather than relying on an environment variable that happened to already be there.

## 10. Fail-Closed Persistence Behavior

`RunnerLedgerPersistenceException` (unchecked) mirrors `ApprovalPersistenceException` exactly: thrown on genuine infrastructure failure (connection loss, a disposed pool, an unexpected internal inconsistency such as a duplicate-insert report with no row found on re-read), never caught anywhere in this codebase and converted into a false `CLAIMED`/`COMPLETED` outcome, and never a signal to fall back to `InMemoryRunnerLedgerRepository` or any other in-memory tracking. `ControlledRunner.execute()` catches it at exactly two points — around `ledger.claim(...)` and around `ledger.recordTerminalEvidence(...)` — both converting it to `BLOCKED` / `RUNNER_LEDGER_UNAVAILABLE`, nothing else.

One correctness gap was found and fixed during this phase's own test-writing: `JdbcRunnerLedgerRepository`'s `claim`, `recordTerminalEvidence`, and its internal `selectExistingClaim` originally caught only `SQLException` around `dataSource.getConnection()` calls. H2's `JdbcConnectionPool#getConnection()` throws a plain `IllegalStateException` (not `SQLException`) once the pool has been disposed, which would have propagated *raw*, unwrapped, past `RunnerLedgerPersistenceException` entirely — an actual fail-closed violation in the sense that the caller would see an undocumented exception type rather than the documented persistence-failure contract, discovered by `Phase2b2JdbcTests#durableStoreFailurePropagatesAndNeverFallsBackToMemory` before it could reach production. All three methods now catch `SQLException | RuntimeException` around connection acquisition, exactly matching the pattern already used (and already proven) in `JdbcApprovalRepository`.

`Phase2b2JdbcTests#simulatedFailureDuringClaimInsertLeavesNoPartialRow` additionally proves, via a fault-injecting `DataSource` proxy (`FaultInjectingDataSource`, mirroring the approval subsystem's own test-only equivalent), that a failure partway through the claim `INSERT` leaves no partial row behind — a subsequent claim attempt for the same id still sees it as genuinely unclaimed.

## 11. Concurrency Model

`InMemoryRunnerLedgerRepository` guards every operation with one `synchronized` lock for its full duration — the same genuine (not merely probable) atomicity `InMemoryApprovalRepository` provides for the approval subsystem. `JdbcRunnerLedgerRepository`'s concurrency guarantee comes entirely from the database's own primary-key uniqueness enforcement on `claim`'s `INSERT`, and from `recordTerminalEvidence`'s `UPDATE ... WHERE runner_request_id = ? AND claim_state = 'CLAIMED'` guard (an update matching zero rows — because the row was already `COMPLETED`, or never claimed — throws `IllegalStateException`, a calling-discipline violation, not a race outcome, since only the single caller that received `CLAIMED` from `claim()` should ever call `recordTerminalEvidence` for that id).

`ControlledRunner` itself holds no lock of any kind in Phase 2B-2 — Phase 2B-1's per-id `ConcurrentHashMap<String, Object>` monitor was removed entirely, since the durable ledger's own atomic claim now fully owns the "exactly one caller proceeds per id" guarantee; two different ids never contend, and two callers racing the same id are serialized by the ledger's atomicity, not by any lock inside `ControlledRunner`.

## 12. Reason/State Model Changes

New `RunnerState`: `REQUEST_CLAIMED`, inserted between `RECEIVED` and `IDENTITY_RESOLVED` — the durable ledger can now fail closed (unavailable, duplicate, mismatch, incomplete) before identity is ever resolved, which Phase 2B-1's state machine had no state name for.

New `RunnerReasonCode` values: `RUNNER_LEDGER_UNAVAILABLE`, `RUNNER_REQUEST_INCOMPLETE`, `RUNNER_IDENTITY_UNAVAILABLE`, `RUNNER_CLASS_NOT_ALLOWED`, `WORKSPACE_ISOLATION_FAILURE`, `ARTIFACT_STAGING_FAILURE`. Still no generic `ERROR` value anywhere.

New `RunnerEvidence` components: `runnerClass`, `runnerEnvironmentScope` (both nullable/empty until identity resolves), matching the persisted ledger schema (§1) without needing a second parallel evidence-carrying type.

## 13. No-Process/No-Mutation Boundary (Re-Verified)

Every Phase 2B-1 structural guarantee still holds and is re-checked by `Phase2b2Tests#runnerPackageStillContainsNoProcessOrShellInvocationAfterPhase2b2`, which extends the original source scan (`ProcessBuilder`, `Runtime.getRuntime().exec`) with the additional literals called for in this phase's authorization: `Runtime.exec`, `/bin/sh`, `"bash"`, `cmd.exe`, `powershell`, `terraform apply`, `terraform destroy`, `terraform import`, `terraform force-unlock` — none present anywhere in `src/main/java/com/iacagent/iacagent/runner` (confirmed both by this test and by an independent manual `grep` across the full package tree, including the new `runner.jdbc` subpackage, during this phase's own review). `RunnerOperation` still has exactly three values; `RunnerState` still has no `APPLYING`/`APPLIED`/`MUTATED` value; `ControlledRunner` still consumes only `ApprovalProvider`, never `ApprovalAuthority`.

## 14. Deferred Phase 2B-3 Items

- Real cloud workload identity/OIDC replacing `HostAttestedRunnerIdentityProvider`'s local-file attestation (Gate C).
- A production-grade durable backend (PostgreSQL) replacing H2 for the runner ledger, with real concurrency validation against it (Gate B) — mirroring the equivalent, still-open gate for approval persistence (Gate A).
- Wiring `ProcessEnvironmentPolicy` into an actual process-invocation path — deliberately not attempted here; this phase only makes the future contract explicit and testable in isolation.
- Per-artifact provider-lock-hash resolution and actually invoking `terraform version` (carried over unfinished from the Phase 2B-1 doc, §13 there — unchanged in this phase).
- A real artifact registry replacing `InMemoryRunnerArtifactStore` (also carried over unfinished from Phase 2B-1).
- Container/process sandboxing for the workspace itself, if the eventual runner host warrants it.
- Lease/expiry policy for stuck `CLAIMED` rows, if manual operator intervention proves insufficient in practice (not attempted in this phase — see §3's reasoning for why an automatic reclaim was deliberately not built).

## 15. Production Hard Gates (Unchanged in Substance, Restated)

```text
Gate A: Approval persistence must be validated against a real external production-grade
datastore, including PostgreSQL integration and concurrency behavior, before Phase 2A
mutation authority.

Gate B: Runner request/evidence replay protection must likewise have a production-capable
external durable implementation and concurrency validation before real execution authority.
(This phase's JdbcRunnerLedgerRepository against H2 is the reference/acceptance backend that
proves the *design* - the claim/record/find contract, the atomicity pattern, the restart and
concurrency test coverage - not a claim that Gate B itself is satisfied.)

Gate C: Production workload identity/OIDC or equivalent verifiable identity must replace
local/static identity before mutation authority.
(HostAttestedRunnerIdentityProvider replaces StaticRunnerIdentityProvider as the *production
path within this phase's own scope* - a real host-fixed attestation source read fresh on every
call - but it is still local attestation, not cloud workload identity/OIDC, so Gate C remains
open exactly as before.)
```

None of these three gates is claimed satisfied by this phase. All three remain explicit prerequisites to any future phase that grants real execution/mutation authority.
