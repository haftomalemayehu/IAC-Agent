# Phase 2B-5: Controlled Terraform Plan + State-Read Boundary

**Status:** Implemented (`com.iacagent.iacagent.runner`, `com.iacagent.iacagent.runner.jdbc`). Adds `TERRAFORM_PLAN` - the seventh and, for this phase, final closed Terraform operation. This is the first phase that produces a real, durable, hash-bound saved-plan artifact and reads real Terraform state. Still no `apply`/`destroy`/`import`/`state *`/`force-unlock`/`taint`/`untaint`/`refresh`/`workspace *`.

**Precise invariant, unchanged and still true:** *No production runner/control-plane operation can represent or dispatch infrastructure or Terraform-state mutation.* `terraform plan` reads state, may read provider APIs, and may acquire/release a normal plan-time backend lock - it never intentionally writes state, and there is no operation, argv shape, or code path in this package that can apply anything. `com.iacagent.iacagent.runner.ControlledTerraformProcess` remains the sole process-spawning class anywhere in `src/main`.

---

## 1. Objective and Scope

Phase 2B-4 could initialize and validate a root module but could not produce a plan. Phase 2B-5 closes that gap with one new operation, `TERRAFORM_PLAN`, that:

1. Resolves a trusted backend/state target via `TrustedBackendResolver` - never from the request or repository.
2. Runs a real (not `-backend=false`) controlled `init` against that backend.
3. Runs `terraform plan -out=<runner-owned-path> -input=false -no-color -detailed-exitcode`.
4. Validates, hashes, and durably stores the resulting saved-plan binary.
5. Runs the existing controlled `show -json` against the exact hashed bytes and parses a plan summary.

Everything from Phase 2B-3/2B-4 that already applied to configuration parsing, source policy, lockfile integrity, executable attestation, and environment isolation applies unchanged to `TERRAFORM_PLAN` - it reuses the same checks, not a parallel copy of them.

## 2. New Closed Operation

`ControlledTerraformOperation.TERRAFORM_PLAN` / `RunnerOperation.TERRAFORM_PLAN` are the only additions to either enum. `TerraformCommandFactory` gained exactly two new methods - `initForPlanCommand` (the real-backend init step) and `planCommand` - both tagged with the same `TERRAFORM_PLAN` operation value (distinguished by argv content, `"init"` vs `"plan"`), so the closed operation surface stays at exactly seven values rather than needing an eighth for the internal init step. `TerraformCommandFactory` now has exactly eight public methods total, verified structurally (`Phase2b4Tests#terraformCommandFactoryBuildsExactlyTheAuthorizedCommandsAndNothingElse`).

## 3. Exact PLAN Argv

```text
<trusted executable path> plan -out=<runner-owned-path> -input=false -no-color -detailed-exitcode
```

Every element is a fixed constant, the trusted executable's own resolved path, or an internally-derived `Path` - there is no parameter through which a caller could introduce `-destroy`, `-refresh-only`, `-target`, `-replace`, `-state`, `-state-out`, an arbitrary `-var`/`-var-file`, an arbitrary `-parallelism`, or `-lock=false`. Proven structurally in `Phase2b5Tests#planCommandArgvContainsDetailedExitcodeAndExcludesDangerousFlags`.

## 4. State-Read Boundary and Trusted Backend Resolution

`TrustedBackendResolver.resolve(repository, environment)` is the ONLY source of backend/state-target truth - there is no `RunnerRequest` field for it, and the repository's own configuration is explicitly forbidden from declaring one (§5). `TerraformBackendResolution` carries a `TerraformStateIdentity` (backendType/canonicalBackendInstanceId/environment/canonicalStateKey - no credentials) plus a concrete `localStatePath`.

**Reference implementation: `ReferenceLocalBackendResolver`.** Maps `(repository, environment)` deterministically (via the same version-prefixed, length-prefixed hash discipline used throughout this package) to a genuine Terraform `local` backend instance rooted under a single trusted `stateRoot` directory. This is a deliberate choice, not a shortcut: the `local` backend requires no cloud credentials at all, so Phase 2B-5 can exercise a genuinely real state-read boundary (real backend init, real state read, real plan-time file locking) without waiting on Gate C's production workload identity. **This is explicitly not a claim that Gate F (production remote-state hardening) is closed** - a real S3/GCS/azurerm/Terraform Cloud resolver would need real backend HA/failure handling, credential brokering, and a governed backend-mapping authority beyond a single local directory.

Proven: same `(repository, environment)` always yields the same `stateIdentitySha256` and `localStatePath` (`#sameRepositoryAndEnvironmentProduceAStableStateIdentity`); different environments/repositories always yield different ones (`#differentEnvironmentsResolveDifferentStateIdentities`, `#differentRepositoriesResolveDifferentStateIdentities`).

## 5. Backend Policy - The Repository May Describe Intent, Never Authority

A staged configuration that declares its own `terraform { backend "..." { ... } }` block is rejected outright with `TERRAFORM_BACKEND_BLOCK_NOT_ALLOWED`, **before `init`/`plan` is ever launched** - detected by extending `TerraformNativeSourceExtractor`/`TerraformJsonSourceExtractor` (a `declaresBackendBlock` fact on `TerraformConfigSourceManifest`) and enforced by the coordinator, the same "extractor reports, coordinator gates" division already used for module-presence and implicit-provider checks. Proven via a marker fixture in `Phase2b5Tests#repositoryDeclaredBackendBlockBlocksBeforeAnyProcessLaunches`.

Because the repository may never declare a backend block, `RunnerWorkspaceManager#writeTrustedLocalBackendFile` is the ONLY backend declaration Terraform ever sees - a runner-owned `_runner_backend.tf` file written into the workspace before `init`:

```hcl
terraform {
  backend "local" {
    path = "<trusted, control-plane-resolved path>"
  }
}
```

Terraform allows at most one `backend` block per configuration; rejecting the repository's own attempt is what guarantees this runner-written file is the only one Terraform will find. No `-migrate-state`/`-force-copy` flag exists anywhere in this package's argv construction.

### 5a. `terraform_remote_state` - A Second, Independent State-Boundary Escape (security amendment)

A plain `backend` block is not the only way a repository can name a state target: Terraform's built-in `data "terraform_remote_state" "x" { backend = "..."; config = {...} }` data source accepts its OWN backend type and config coordinates, entirely independent of whatever `TrustedBackendResolver` resolved for the primary backend. Because it is backed by the built-in `terraform` provider - which is, correctly, exempt from ordinary provider-source-declaration policy (it ships inside the Terraform binary and cannot be redirected to an arbitrary source; see `TerraformNativeSourceExtractor#BUILTIN_PROVIDER_LOCAL_NAME`) - this data source can survive both the backend-block check in §5 and normal provider-source policy while still letting a repository read (and thereby exfiltrate, or use to smuggle plan-time state-dependent logic from) an arbitrary attacker-chosen backend/state target.

This phase closes it as a dedicated, separate check rather than folding it into backend-block detection: `TerraformNativeSourceExtractor`/`TerraformJsonSourceExtractor` recognize a `data "terraform_remote_state" "..."` block (native syntax) or a `data.terraform_remote_state` key (JSON syntax) and set `declaresRemoteStateDataSource` on `TerraformConfigSourceManifest`; `ControlledTerraformOperationCoordinator#executePlan` blocks with `TERRAFORM_REMOTE_STATE_DATA_SOURCE_NOT_ALLOWED` before `init`/`plan` is ever launched, **regardless of the backend type or coordinates declared inside the data source's own `config` block** - a `local` backend pointed at an unexpected path is blocked exactly like an `s3` backend pointed at an attacker-controlled bucket. Like `declaresBackendBlock`, this check applies only to `TERRAFORM_PLAN` (the only operation that uses a real backend or reads real state) - `TERRAFORM_INIT`/`TERRAFORM_VALIDATE`/`TERRAFORM_PROVIDERS_SCHEMA` always force `-backend=false` and never launch as far as evaluating a `terraform_remote_state` data source's config in any state-reading sense.

This phase deliberately does **not** attempt to allowlist any repository-authored remote-state backend coordinates - there is no mechanism, however narrow, by which a repository can get `terraform_remote_state` to resolve. An ordinary (non-`terraform_remote_state`) `data` block is unaffected and continues to follow the same implicit-provider rules as before (`Phase2b5Tests#ordinaryDataSourceIsNotFalselyBlockedByRemoteStateCheck`). Trusted cross-state dependencies - e.g. a plan legitimately needing an output from another repository's approved state - require a **future control-plane-mediated resolver** (analogous to `TrustedBackendResolver` itself) that resolves a request for "this trusted named dependency" to a control-plane-approved backend/state target, never a backend/config literal the repository authored. That resolver does not exist yet and is out of scope for Phase 2B-5.

Proven via `Phase2b5Tests#nativeRemoteStateDataSourceWithLocalBackendBlocksBeforeAnyProcessLaunches`, `#nativeRemoteStateDataSourceWithS3BackendBlocksRegardlessOfBackendType`, `#jsonSyntaxRemoteStateDataSourceBlocksBeforeAnyProcessLaunches`, and `#ordinaryDataSourceIsNotFalselyBlockedByRemoteStateCheck` - each using the marker-fixture pattern to prove `init` never launches when blocked.

## 6. Read-Only Backend Semantics

`TERRAFORM_PLAN` may: initialize backend connectivity, read state, acquire/release a normal plan-time backend lock, and refresh remote objects via ordinary Terraform plan semantics (provider API reads happen here - see §19). It may not, and has no code path that could: write new state intentionally, push/migrate/replace state, remove state entries, import resources, force-unlock, or apply. This is a semantic property of which Terraform subcommands this package's closed argv builders can construct (`plan` only, never `apply`/`state push`/`state rm`/`force-unlock`/`import`), not a runtime check on Terraform's own behavior.

## 7. State Identity

`TerraformStateIdentity(backendType, canonicalBackendInstanceId, environment, canonicalStateKey)` plus `sha256Hex()` - same version-prefixed, length-prefixed, unambiguous encoding as `RunnerRequest#fingerprintSha256()`/`TerraformConfigIdentity`. Carries no credentials. The same repository/config against a different state target (different environment, or in principle a different resolver-configured backend instance) always produces a different `stateIdentitySha256`.

## 8. Backend Credential Boundary

`TerraformCredentialProvider.obtain(request, stateIdentity)` returns `TerraformCredentialMaterial(environmentVariables, sourceIdentifier)` - environment variables are added directly to the launched process's environment and NEVER placed in any evidence record; only `sourceIdentifier` (a non-secret label) is recorded. `NoOpTerraformCredentialProvider` is the Phase 2B-5 reference implementation - honest, since `ReferenceLocalBackendResolver`'s local backend needs no cloud credentials at all (`sourceIdentifier` = `"none:local-backend-reference"`). **Gate C remains open** until a real workload-identity-backed implementation exists.

Proven: `TerraformPlanEvidence` has no field for credential values at all (only `credentialSourceIdentifier`), and a fake provider returning a real secret value is proven absent from both `evidence.toString()` (`Phase2b5Tests#credentialValuesNeverAppearInEvidenceOrItsSerializedForm`) and its JSON-serialized form (`Phase2b5JdbcTests#terraformPlanEvidenceJsonNeverContainsCredentialMaterial`).

## 9. Environment

Unchanged base discipline: `ProcessBuilder.environment().clear()` then only trusted values (`TerraformInitProcessEnvironmentPolicy`'s `TF_CLI_CONFIG_FILE`/`TF_DATA_DIR`/`TF_PLUGIN_CACHE_DIR`/`HOME`/`TMPDIR`, plus whatever `TerraformCredentialProvider` explicitly supplies). `TerraformCommandFactory#initForPlanCommand`/`planCommand` accept an `extraEnvironmentVariables` map that is layered on top of the base policy's output - never a replacement of it, and never sourced from anywhere but the credential provider.

## 10. Provider/Module Boundary - Unchanged

`TERRAFORM_PLAN` reuses the exact same pre-init gates as `TERRAFORM_INIT`: module-block presence blocks unconditionally (`TERRAFORM_MODULE_DEPENDENCY_GRAPH_UNRESOLVED`), an implied-but-undeclared provider blocks (`TERRAFORM_PROVIDER_REQUIREMENT_IMPLICIT`), and every declared provider source is checked against `TerraformSourcePolicy`. Gate E remains open. Proven in `Phase2b5Tests#moduleBlockBlocksPlanUnconditionally`/`#implicitProviderBlocksPlanBeforeInitEverRuns`.

## 11. Plan Input Identity

`TerraformPlanInputIdentity.computeSha256` binds `configSha256`, `stateIdentitySha256`, `providerLockHashExpected`, `executableSha256Expected`, `terraformVersionExpected`, `environment`, a fixed `executionMode` string (`"PLAN_LOCAL_BACKEND_REFERENCE"` for this phase - itself part of the hash, so a future mode change automatically changes identity), and a sorted, deduplicated list of `TerraformVariableInput`s - all via the same version-prefixed, length-prefixed encoding discipline as every other identity hash in this package. Proven to change independently for each input dimension: state target, provider lock hash, executable hash, environment, and variable inputs each produce a different `planInputSha256` when varied in isolation (`Phase2b5Tests` §"plan input identity").

## 12. Terraform Variables

`TerraformVariableInput(name, canonicalJsonValue, sensitive)` is defined, validated, and unit-tested, and has a well-defined slot in `TerraformPlanInputIdentity`'s encoding - but is **not wired into `executePlan`'s actual argv/tfvars-file construction in this phase**, per the explicit permission in the Phase 2B-5 authorization ("acceptable to leave variable support out of Phase 2B-5 rather than implementing it loosely"). `executePlan` always calls the identity function with an empty variable list. A future phase wiring real variable support (a runner-generated `.tfvars.json`, `-var-file=<runner-owned-path>`, redaction of `sensitive` values from evidence) can build directly on this type without changing the identity encoding's shape.

## 13. Plan Artifact Path

`RunnerWorkspaceManager#preparePlanArtifactPath(workspace)` computes `<workspace>/plan/tfplan` - never a caller-supplied path - creates the parent directory, and rejects outright (before any process launches) if anything already exists at that exact path (symlink or otherwise), via `Files.exists(path, LinkOption.NOFOLLOW_LINKS)`. Proven in `Phase2b5Tests#preExistingSymlinkAtThePlanPathIsRejectedBeforePlanLaunches` (marker fixture: `plan` never runs).

## 14. Plan Artifact Hashing

`RunnerWorkspaceManager#validateSavedPlanArtifact(planPath)` runs immediately after `terraform plan` reports success (exit 0) or changes-present (exit 2 via `-detailed-exitcode`): rejects a symlink or non-regular-file outright, re-resolves the real path and re-confirms workspace containment, then the coordinator reads the exact bytes and computes `planSha256` via SHA-256. Never inferred from the plan's JSON representation - the binary saved-plan bytes are the sole authoritative identity, exactly as the Phase 2B-5 authorization requires. Proven in `Phase2b5Tests#planHashIsComputedFromTheExactSavedPlanBytesAndMatchesTheStoredArtifact` and `#planArtifactMustBeARegularFileAfterTheCommandRuns` (a "successful" exit that never actually wrote a file is rejected as `TERRAFORM_PLAN_ARTIFACT_INVALID`, not trusted).

## 15. Plan JSON

`terraform show -json <exact-saved-plan>` runs via the existing, unmodified controlled SHOW command. Immediately before constructing the SHOW command, the coordinator re-reads and re-hashes the saved-plan bytes and compares against the hash it just computed in §14, blocking with the existing `TERRAFORM_PLAN_HASH_MISMATCH` reason code on any difference - the same TOCTOU discipline `TERRAFORM_SHOW_PLAN_JSON` already established in Phase 2B-3, reused rather than re-invented.

**Disclosed limitation:** unlike Phase 2B-3's `TERRAFORM_SHOW_PLAN_JSON` (where the plan-hash check runs against a hash established in an earlier, temporally-separate `ControlledRunner` step, giving a real window a test can inject tampering into), `TERRAFORM_PLAN`'s own two hash reads happen back-to-back within the same synchronous method with no intervening step in this phase's implementation - so there is currently no scheduled gap for an attacker (or a test) to exploit between them. The check is retained as genuine defense-in-depth (it would catch tampering from, e.g., a concurrent process on the same host between the two reads) and as a safety net for any future refactor that introduces a real gap (e.g., an async artifact-store write between hash and SHOW) - but this phase does not claim to have proven a race is caught, only that the mechanism exists and runs on every call.

`PlanJsonParser`/`PlanSummary`/`RiskEngine` (from `com.iacagent.iacagent`) are reused completely unmodified - `TerraformPlanEvidence` carries the extracted change counts (create/update/replace/destroy), and the same `PlanSummary` a future risk/PR-review integration will consume is directly obtainable from the SHOW output this phase already produces. Proven in `Phase2b5Tests#showRunsAgainstTheExactSavedPlanAndExtractsChangeCounts`, including a direct call into `RiskEngine.assess` on the extracted summary to prove the contract still fits.

## 16. Plan Evidence

`TerraformPlanEvidence` embeds as `RunnerEvidence#terraformPlanEvidence()` - the same "embedded, not a separate ledger row" pattern every other Terraform evidence type in this package uses. Carries: identity bindings (`configSha256`/`stateIdentitySha256`/`planInputSha256`), executable/version expected+observed, `providerLockHash`, backend identity (`backendType`/`backendInstanceId`), `credentialSourceIdentifier` (never a value), plan artifact identity (`planArtifactId`/`planSha256`/`planByteSize`), SHOW output identity (`showJsonSha256`/`showJsonByteSize`), change counts, exit code/timeout/process state/reason codes, and timestamps. No secrets, no raw stdout/stderr content, no raw plan JSON. Durably persisted via `V4__add_terraform_plan_evidence.sql` + hand-written `TerraformPlanEvidenceJson`, proven via a real H2 round-trip in `Phase2b5JdbcTests`.

## 17. Plan Result Semantics

`TerraformProcessState` is reused, not extended with new values - `SUCCEEDED` (exit 0, no changes) and `COMMAND_REPORTED_DIFFERENCE` (exit 2, changes present) are both legitimate, non-failure outcomes (`TerraformPlanEvidence#succeeded()` is true for both); `FAILED` covers a genuine plan failure (exit 1 or any other unexpected code) as well as a downstream artifact/hash/SHOW failure after a nominally-successful exit; `BLOCKED` covers every pre-launch policy/attestation/backend-resolution failure; `TIMED_OUT`/`OUTPUT_LIMIT_EXCEEDED` are unchanged from every other operation. This reuses the exact "fmt-check differences are not a failure" precedent from Phase 2B-3 rather than inventing a parallel `PLAN_NO_CHANGES`/`PLAN_CHANGES_PRESENT` state pair - the distinction is fully recoverable from `TerraformPlanEvidence#hasChanges()`.

## 18. Detailed Exit Codes

`-detailed-exitcode` is used (the Phase 2B-5 authorization's stated strong preference). Semantics implemented exactly: `0` = success/no changes → `SUCCEEDED`; `2` = success/changes present → `COMMAND_REPORTED_DIFFERENCE`, never treated as a failure; `1` or any other code → `FAILED`/`TERRAFORM_PLAN_FAILED`. Proven in `Phase2b5Tests#planExitCodeZeroIsSuccessWithNoChanges`, `#planExitCodeTwoIsSuccessWithChangesNotFailure`, `#planExitCodeOneIsAGenuineFailure`, `#planUnexpectedExitCodeIsTreatedAsFailure`.

## 19. Refresh Semantics

No `-refresh=false` is ever added - normal Terraform plan refresh semantics apply, so a plan genuinely reflects current infrastructure. This means provider API reads occur during `plan` - stated explicitly rather than left implicit, since it is a real, if bounded, network/API-access surface this phase's process boundary does not itself sandbox (Gate D).

## 20. Locking

No `-lock=false` is ever added - normal Terraform state locking stays enabled, including for the reference `local` backend (which uses real local-file locking). No force-unlock capability exists anywhere in this package.

### 20a. Deterministic Lock/Backend Failure Classification (security amendment)

The original Phase 2B-5 implementation left `TERRAFORM_STATE_LOCK_FAILED`/`TERRAFORM_STATE_LOCK_TIMEOUT` defined but unreachable, on the stated grounds that distinguishing a lock-specific failure would require inspecting raw stderr content this package deliberately never persists. The amendment authorization explicitly permitted a narrower capability that does not require persisting anything: **transient, bounded inspection of already-captured stderr, inside trusted deterministic code, solely to emit a sanitized classification** - the raw bytes themselves are never stored, logged, or placed in an exception message.

This is implemented as two additive pieces:

- `TerraformProcessResult` (used only by `TERRAFORM_PLAN`'s init-for-plan/plan steps and nothing else) now exposes a raw bounded `stderr()` accessor alongside the existing `stdout()`, populated the same way (`ControlledTerraformProcess`'s already-internally-captured `BoundedStreamReader#capturedBytes()`, previously computed but never surfaced beyond size+hash). `stderrSize`/`stderrSha256` remain the only *persisted* representation of stderr; `stderr()` itself must never reach evidence, ledger JSON, or an exception message - only `ControlledTerraformOperationCoordinator#classifyStderrFailure`'s *output* (a `RunnerReasonCode`, or `null`) is allowed to escape.
- `classifyStderrFailure(byte[] stderr)` performs a fixed, deterministic, case-insensitive substring check - no LLM, no heuristic scoring - wired into both the init-for-plan failure path (`classifyNonPlanFailure`) and the plan-step failure path (`interpretPlan`'s exit-code-not-0-or-2 branch):
  - stderr mentions **"state lock"** and **"timeout"** → `TERRAFORM_STATE_LOCK_TIMEOUT`.
  - stderr mentions **"state lock"** without timeout wording → `TERRAFORM_STATE_LOCK_FAILED`.
  - stderr mentions **"backend"** together with failure/configuration-error wording (`"error configuring"`/`"failed to"`/`"could not"`) → `TERRAFORM_STATE_BACKEND_UNAVAILABLE`.
  - anything else → `null`, and the caller falls back to the existing generic `TERRAFORM_PLAN_INIT_FAILED`/`TERRAFORM_PLAN_FAILED`.

**Epistemic humility, honored explicitly.** Terraform's "lock already held" and "lock acquisition timed out" failures share the same base "Error acquiring the state lock" banner text; only the timeout case additionally emits distinct timeout wording. When stderr mentions a state lock but not that timeout-specific wording, this method deliberately returns the *less specific* `TERRAFORM_STATE_LOCK_FAILED` rather than guessing - it never fabricates a distinction the text does not actually support. The same discipline applies to the backend-unavailable check: both a `"backend"` mention and clear failure wording must be present, or the result falls through to `null` rather than a speculative classification.

**Deterministic timeout window.** `TerraformCommandFactory` now adds a fixed, internally-controlled `-lock-timeout=10s` to both `initForPlanCommand` and `planCommand`'s argv - never derived from or exposed to `RunnerRequest` (verified by the existing `runnerRequestHasNoBackendOrStateField` structural test, and directly by `Phase2b5Tests#lockTimeoutArgIsFixedAndInternallyControlledInBothInitAndPlanArgv`). Without a nonzero bound, Terraform's own default (`0s`, fail immediately on contention) would make "held" and "timed out" indistinguishable in practice regardless of stderr wording; a small fixed bound gives a genuine timeout window to observe.

Proven via `Phase2b5Tests#initLockAlreadyHeldStderrClassifiesDeterministically`, `#initLockAcquisitionTimeoutStderrClassifiesDeterministically`, `#initBackendUnavailableStderrClassifiesDeterministically`, `#initUnrelatedFailureStderrFallsBackToGenericInitFailure` (proving the no-fabrication fallback), `#planStepLockFailureStderrClassifiesDeterministicallyToo` (proving the same classification applies at the plan step, not only init-for-plan), and `#lockTimeoutArgIsFixedAndInternallyControlledInBothInitAndPlanArgv`.

## 21. Plan Artifact Immutability

After creation, the saved-plan file is immutable by control-plane convention: `planSha256` is recorded in evidence and in the durable artifact store, and any later stage (a future approval/apply phase) must re-hash before use rather than trusting a previously-recorded hash. Filesystem-mode read-only protection is not currently applied to the plan file itself (unlike staged `.tf`/lockfile content elsewhere in this package) since the file lives only transiently in the ephemeral workspace before being copied into the durable store - cryptographic revalidation via the durable store's own content-addressed identity is what actually matters, not filesystem permissions on a soon-to-be-deleted workspace file.

## 22. Saved Plan Lifecycle - `TerraformPlanArtifactStore`

`TerraformPlanArtifactStore` (`store`/`resolve`/`metadata`) is the trusted durable home for saved-plan binaries - the workspace that created a plan is cleaned up at the end of the same `ControlledRunner#execute` call, so the plan must be copied out before that happens. `store` always derives `planArtifactId` from the plan's own SHA-256 (`"sha256-" + planSha256`) - content-addressed, never a caller-supplied id.

**Reference implementation: `FileBackedTerraformPlanArtifactStore`.** One directory per `planArtifactId` under a trusted root, holding the exact plan bytes (write-to-temp-then-atomic-rename, the same discipline as `RunnerWorkspaceManager`) plus a hand-written JSON metadata sidecar. **Explicitly non-production and unencrypted** - acceptable per the Phase 2B-5 authorization ("a file-backed durable reference store is acceptable if explicitly non-production"), not a claim that Gate A/B's durable-storage requirements extend to plan artifacts. Proven via a real store/resolve round-trip in `Phase2b5Tests#planHashIsComputedFromTheExactSavedPlanBytesAndMatchesTheStoredArtifact`.

### 22a. Sensitive-Artifact Security Boundary (security amendment)

HashiCorp documents that a saved plan file can contain the full configuration, planned values, plan options, and input variables - including sensitive values in cleartext - and treats both state and plan files as sensitive artifacts. The original Phase 2B-5 implementation stored plan binaries durably but applied none of the security boundary this implies. This amendment hardens `FileBackedTerraformPlanArtifactStore` as follows:

- **Trusted canonical root, established once.** The constructor creates (if absent) and resolves the artifact root's real path (`Path#toRealPath`) exactly once; every subsequent operation is scoped under that resolved root, never re-derived per call.
- **Artifact paths derived internally only.** `store()` never accepts a caller-supplied id - `planArtifactId` is always `"sha256-" + sha256Hex(planBytes)`. `resolve()`/`metadata()` validate a caller-supplied `planArtifactId` against a strict `^sha256-[0-9a-f]{64}$` pattern *before* it is ever resolved to a path - no `..`, absolute path, or path separator in the input can influence the lookup. A value that fails the pattern is treated as not-found, never even reaching path resolution.
- **No symlink escape.** The artifact directory, the plan file, and the metadata file are each checked with `Files#isSymbolicLink` before being trusted, and the artifact directory's resolved real path is rechecked for containment under the trusted root after every creation/lookup - the same two-step discipline `RunnerWorkspaceManager` already applies to workspace paths. `store()` additionally refuses to write through a pre-existing symlink at any of the three positions it is about to create.
- **`resolve()` requires a regular file** at both the plan and metadata positions (not a directory, not a symlink, not any other file type) before reading either.
- **Resolve-time integrity verification.** On every `resolve()`, the plan bytes are re-hashed from what was actually read, and the result is rejected (as `Optional.empty()` - indistinguishable from "never existed", not a distinguishing exception) unless *all* of the following agree: the metadata's own recorded `planArtifactId` equals the id that was requested; the metadata's recorded `planSha256` equals the freshly recomputed hash of the bytes just read; and the requested id itself equals `"sha256-" + that recomputed hash`. `metadata()` applies the lighter-weight subset of this check that does not require reading the (potentially large) plan binary: the metadata's own `planArtifactId` and `planSha256` fields must be internally consistent with the requested id.
- **Atomic writes**, unchanged from before: write-to-temp then `ATOMIC_MOVE`, so no partially-written plan or metadata file is ever observable at its final path.
- **POSIX permissions, best-effort only.** On a POSIX-supporting filesystem, the artifact root and every artifact directory are restricted to owner-only (`0700`), and both the plan binary and the metadata sidecar (which itself carries repository/commit/environment/state-identity identifiers) to owner read/write-only (`0600`) - all via the same try/catch-`UnsupportedOperationException` best-effort pattern `RunnerWorkspaceManager#makeReadOnlyBestEffort` already established. **POSIX support is never made mandatory** - a non-POSIX filesystem silently no-ops these calls rather than failing; `Phase2b5Tests#posixPermissionsAreAppliedWherePlatformSupportsThem` asserts the exact modes only under `Assumptions.assumeTrue(...supportedFileAttributeViews().contains("posix"))`, so the test itself is skipped (not failed) where POSIX does not apply.
- **No plan content anywhere it could leak.** Plan bytes and decoded plan contents are never placed in a log message, an exception message, `RunnerEvidence`/`TerraformPlanEvidence`, ledger JSON, or artifact metadata - only sizes and hashes are ever recorded. `Phase2b5Tests#planContentIsAbsentFromMetadataAndEvidence` proves a distinctive plan-content marker does not appear in the evidence's `toString()`, the metadata's `toString()`, or the raw `metadata.json` sidecar on disk.
- **The one previously-unguarded call site is now fail-closed.** `ControlledTerraformOperationCoordinator#interpretPlan`'s call to `planArtifactStore.store(...)` is now wrapped in a `try/catch(RuntimeException)` that maps any hardening-validation failure inside `store()` to `TERRAFORM_PLAN_ARTIFACT_INVALID` structured evidence, rather than letting it propagate as an uncaught exception out of `executePlan`/`ControlledRunner#execute`.

Proven via `Phase2b5Tests#traversalViaCallerSuppliedArtifactIdIsImpossible`, `#symlinkedArtifactDirectoryIsRejected`, `#symlinkAncestorEscapeAtThePlanFileIsRejected`, `#tamperedPlanBytesAreRejectedOnResolve`, `#metadataHashMismatchIsRejectedOnResolve`, `#wrongIdentityMetadataIsRejectedOnResolve`, `#planContentIsAbsentFromMetadataAndEvidence`, and `#posixPermissionsAreAppliedWherePlatformSupportsThem`.

This remains a reference implementation, not a production artifact store: it prevents this JVM process's own callers from being tricked into trusting the wrong, tampered, or maliciously-relocated bytes, but it does **not** provide encryption-at-rest, a real multi-tenant access-control model, or a retention/deletion policy - see Gate F (§28), which now explicitly covers plan-artifact-at-rest security alongside backend/state hardening.

## 23. Plan-Hash Chain Lineage - Preserved, Not Duplicated

`TerraformPlanEvidence#planSha256()` is computed by the exact same SHA-256-over-exact-bytes discipline `ApprovalRecord`/`ExecutionIdentity` already use elsewhere in this codebase (Phase 2A/2C) - this phase introduces no second, competing notion of "plan identity." A future Phase 2C/2A integration binding an `ApprovalRecord` to a Phase 2B-5-produced plan needs no translation layer between the two - `planSha256` here IS the same identity concept, now for the first time backed by a plan this runner actually generated rather than one supplied externally.

## 24. No Approval Issuance Here

`TERRAFORM_PLAN` produces evidence (including a plan summary future risk/cost/PR-review logic can consume) and durably stores the plan artifact. It does not issue, evaluate, or reference any `ApprovalRecord` - human approval remains entirely Phase 2C's responsibility, unchanged.

## 25. No Apply Authority - Structural Proof

`ControlledTerraformOperation`/`RunnerOperation` have no `APPLY`/`DESTROY` value (verified structurally - `Phase2b5Tests#terraformPlanIsAClosedOperationInBothEnums`); `TerraformCommandFactory` has exactly eight public methods, none named or shaped to construct `apply`/`destroy` argv; there is no generic `execute(List<String>)`/`run(String...)` anywhere in `src/main`. The runner can create a `tfplan` file; nothing in this package can execute it.

## 26. Sole Process-Spawning Class - Preserved

`ControlledTerraformProcess` is unchanged by this phase and remains the only class in `src/main` that constructs a `ProcessBuilder`.

## 27. Test Coverage Summary

51 tests in `Phase2b5Tests` (structural enum/argv checks; trusted backend/state resolution determinism; repository-declared-backend-block rejection; `terraform_remote_state` state-boundary-escape rejection in both native and JSON syntax, including the non-remote-state-data-source negative case; module/implicit-provider gate reuse; executable attestation reuse; init-for-plan failure isolation; `-detailed-exitcode` 0/1/2/other semantics; deterministic state-lock/backend failure classification at both the init-for-plan and plan steps, including the no-fabrication generic-fallback case; the fixed internally-controlled `-lock-timeout` argv check; plan artifact path/symlink/regular-file safety; plan hash + durable artifact store round-trip; the durable artifact store's sensitive-artifact security boundary - traversal, symlinked artifact directory, symlinked ancestor plan file, tampered plan bytes, metadata/hash mismatch, wrong-identity metadata, plan-content absence from metadata/evidence, and POSIX permission modes where the platform supports them; SHOW/plan-summary integration including a `RiskEngine` reuse check; malformed SHOW JSON handling; five `planInputSha256` differentiation tests plus one stability test; credential redaction from `toString()`; two full `ControlledRunner` end-to-end tests including duplicate-request replay protection; a not-wired-blocks-not-throws test). Plus 2 tests in `Phase2b5JdbcTests` (real-database round-trip persistence; credential redaction from the JSON serialization specifically). 340 tests total across the full suite, stable across 5 fresh `--rerun-tasks` reruns.

## 28. Production Hard Gates

```text
Gate A: Approval persistence needs real PostgreSQL integration + concurrency verification. Still open.
Gate B: Runner ledger needs real PostgreSQL integration + concurrency verification. Still open.
Gate C: Runner identity needs real workload identity/OIDC. TerraformCredentialProvider is a real
abstraction now, but NoOpTerraformCredentialProvider (the only implementation) supplies no
credentials at all - honest for the local-backend reference resolver, but Gate C is not touched by
this phase. Still open.
Gate D: Production runner sandbox - OS/container isolation, resource controls, network policy.
TERRAFORM_PLAN is the first operation with a REAL (if narrow) network/provider-API-read surface
(§19) - still no OS/container-level enforcement of it. Still open.
Gate E: Module/provider supply-chain governance. Unchanged - module execution remains fully
prohibited for TERRAFORM_PLAN too (§10). Still open.
Gate F (new, 2B-5; extended by the security amendment): Production remote-state/backend hardening -
production backend credentials, backend HA/failure behavior, backend-mapping governance beyond a
single trusted local directory, backend observability, state encryption/access policy. Extended to
explicitly cover plan-artifact-at-rest security: encryption-at-rest (e.g. KMS-backed), a real
multi-tenant access-control model, and a retention/deletion policy for durably stored plan
binaries - `FileBackedTerraformPlanArtifactStore`'s hardening (§22a) prevents this JVM process's own
callers from trusting tampered/relocated/misidentified bytes, but provides none of encryption,
access control, or retention. ReferenceLocalBackendResolver/FileBackedTerraformPlanArtifactStore are
real, tested, non-heuristic reference implementations - not a claim that Gate F is closed.
```
None of A/B/C/D/E/F is satisfied by this phase.

## 29. Why `apply` Remains Impossible

Nothing added in this phase changes the closed-enum argument from Phase 2B-3/2B-4: both operation enums are still fixed with no `APPLY`/`DESTROY` value, `TerraformCommandFactory` has exactly eight public command-building methods (all producing read/plan-only argv), and there is no generic execution API anywhere in `src/main`. `TERRAFORM_PLAN` produces a durable, hash-bound artifact for a LATER phase to review, approve, and (only then, under separate authority) apply - it cannot apply anything itself.

## 30. Deferred / Out of Scope

- `terraform apply`/`terraform destroy`/`terraform import`/`terraform state *`/`terraform force-unlock`/`terraform taint`/`terraform untaint`/`terraform refresh`/`terraform workspace *` - unrepresentable by any operation value.
- Real remote backend types (S3/GCS/azurerm/Terraform Cloud) and everything Gate F covers.
- Real workload identity/OIDC-backed credentials (Gate C) - `NoOpTerraformCredentialProvider` is honest only because the reference backend needs none.
- A trusted, control-plane-mediated cross-state dependency resolver (§5a) - the mechanism a future phase would need to let a plan legitimately depend on another repository's approved state, without ever letting the repository author its own backend/config coordinates the way `terraform_remote_state` does today.
- Encryption-at-rest, multi-tenant access control, and a retention/deletion policy for durably stored plan artifacts (§22a, folded into Gate F) - the security-amendment hardening prevents this JVM's own callers from trusting tampered/misidentified bytes, but is not a production artifact-security posture.
- Wired variable/`.tfvars.json` support (§12) - the type and identity-binding slot exist; the runtime plumbing does not yet.
- A genuinely time-separated TOCTOU test for the plan-hash-before-SHOW recheck (§15) - the check runs on every call, but this phase's synchronous flow has no real gap for a test to exploit.
- Module execution of any kind (§10, carried over from Phase 2B-4).
- OS/container-level sandboxing/network enforcement (Gate D, carried over).
- A production-grade durable backend (PostgreSQL) for approval/runner-ledger persistence (Gates A/B, carried over).
- **Not blocking Phase 2B-5, flagged by the user for a future phase:** HashiCorp documents that a saved plan can depend on the filesystem layout, OS/CPU architecture, and exact provider plugin binaries present when it was created - a plan generated on one runner is not unconditionally safe to apply on another. A future Phase 2A exact-apply precondition should verify platform identity (OS/CPU architecture) and provider-runtime identity compatibility between the runner that generated an approved plan and the runner that later applies it, before any apply is permitted against that plan. Nothing in Phase 2B-5 attempts this - `TERRAFORM_PLAN`'s evidence records the executable's own SHA-256/version (§9 of Phase 2B-3's design) but nothing about the host OS/architecture or provider plugin binary identity specifically for later apply-compatibility checking.
