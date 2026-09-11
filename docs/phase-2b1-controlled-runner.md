# Phase 2B-1: Controlled Runner Boundary

**Status:** Implemented (`com.iacagent.iacagent.runner`). No Terraform execution, no infrastructure mutation, no shell/process invocation exists anywhere in this phase.

**Upstream binding references:** `docs/roadmap-phase-2.md`, `docs/phase-2a-execution-contract.md`, `docs/phase-2a-threat-model.md`, `docs/Master-Prompt.txt`. Phase 2C-1/2C-2 approval authority and persistence contracts are consumed unchanged (`ApprovalProvider`, `ApprovalValidator`, `ExecutionIdentity`) — this phase adds no new approval semantics and reuses the existing validator rather than reimplementing identity/expiry/revocation/supersession comparison logic.

**What this phase answers, and what it deliberately does not:**

```text
Answers:
  What can the runner execute?           -> VERIFY_ARTIFACT / VERIFY_CONTEXT / PREPARE_EXECUTION only
  Who may ask it to execute?              -> anyone holding an ApprovalProvider-backed approval; identity is the runner's own, not the caller's
  What artifact may it consume?           -> only what RunnerArtifactStore resolves, re-hashed independently
  What identity/context is bound?         -> RunnerIdentity (host-derived), approval (Phase 2C), toolchain (runner-observed)
  How is execution isolated?              -> one ephemeral workspace per runnerRequestId, content-addressed staging
  How does it fail closed?                -> every failure path returns BLOCKED with a specific reason code
  What evidence does it emit?             -> one RunnerEvidence record per attempt, expected+observed values, never overwritten

Does NOT answer:
  How do we apply Terraform yet?          -> not this phase. No APPLY operation exists to answer it with.
```

---

## 1. Runner Trust Boundary

Everything below is treated as untrusted input, exactly as inherited from the Phase 2A threat model: repository contents, PR text/comments, Terraform files, plan contents, LLM output, natural-language instructions, caller-supplied command strings, arbitrary environment variables.

The runner boundary exposes exactly one typed entry point: `ControlledRunner.execute(RunnerRequest)`. There is no `execute(String command)`, no shell/process invocation, and no operation value representing mutation anywhere in the `com.iacagent.iacagent.runner` package — verified by `Phase2b1Tests#runnerPackageContainsNoProcessInvocation` (source-scan for `ProcessBuilder`/`Runtime.exec`) and `#controlledRunnerExposesNoGeneralCommandInterface` (reflection: `ControlledRunner` has exactly one public method, and it takes no `String` parameter).

## 2. Request Contract

`RunnerRequest` (record): `runnerRequestId, repository, commitSha, environment, planArtifactId, planSha256, terraformVersion, providerLockHash, approvalId, requestedOperation`. All fields required and non-blank (enforced in the compact constructor). `requestedOperation` is the closed `RunnerOperation` enum — `VERIFY_ARTIFACT`, `VERIFY_CONTEXT`, `PREPARE_EXECUTION` — no string field, no mutation value exists to select.

Deliberately absent from this type: any identity-shaped field (`runnerId`, `trusted`, `environmentScope`), any approval attribute beyond the reference `approvalId`, any raw command/shell/URL field. `Phase2b1Tests#runnerRequestHasNoIdentityShapedField` asserts this structurally via `RunnerRequest.class.getRecordComponents()`.

## 3. Identity Source

`RunnerIdentity(runnerId, runnerClass, environmentScope, trusted)` is produced exclusively by `RunnerIdentityProvider.currentIdentity()`, injected into `ControlledRunner`'s constructor — never read from a `RunnerRequest`. Phase 2B-1 ships `StaticRunnerIdentityProvider`: a fixed identity configured once, at construction, standing in for "however the host/deployment provisioned this runner instance" (a machine role, a service account) — a request arriving at a runner cannot change what that runner believes about itself.

**Invariant:** a caller cannot self-assert identity because there is no parameter, field, or code path through which one could attempt to. This is structural (no field exists to read one from), not a runtime check that could be bypassed.

**Deferred to 2B-2:** real dynamic attestation (OIDC workload identity). Not attempted here because it is not trivial/local-only, per the phase's own scope instruction.

Two identity-derived checks run first, in order: `trusted` (→ `RUNNER_IDENTITY_UNTRUSTED` if false), then `environmentScope.contains(request.environment())` (→ `RUNNER_ENVIRONMENT_NOT_ALLOWED` if not). An untrusted identity is never checked for environment scope — the more fundamental failure is reported.

## 4. Artifact Trust Model

`RunnerArtifactStore.resolve(planArtifactId) -> Optional<StoredArtifact>` is the only way `ControlledRunner` obtains artifact bytes. `StoredArtifact` carries the store's own `recordedSha256` (set when the artifact was staged/cataloged, independent of anything a caller claims) alongside the actual `content`.

Verification, in order:
1. `resolve()` returns empty → `ARTIFACT_NOT_FOUND`, BLOCKED.
2. SHA-256 is recomputed from `content` — never trusted from `recordedSha256` or from the request alone.
3. The recomputed hash must match **both** `recordedSha256` (store-internal integrity) **and** `request.planSha256()` (does this artifact match what the approval actually covers). Either mismatch → `ARTIFACT_HASH_MISMATCH` (the same reason code for both causes, mirroring the Phase 2A execution contract's own choice not to distinguish "tampered" from "wrong artifact" from "corrupted" — the enforcement action is identical).

No field on `RunnerRequest` or `StoredArtifact` is ever interpreted as a URL to fetch; there is no code path that resolves a caller-supplied location. `InMemoryRunnerArtifactStore` (Phase 2B-1's deterministic catalog, populated only by test/fixture code) stands in for a real artifact registry a later 2B slice would introduce.

## 5. Approval Dependency

`ControlledRunner` consumes `ApprovalProvider` — read-only — never `ApprovalAuthority`. It cannot issue, revoke, or supersede anything; it can only ask whether an approval is valid for a given `ExecutionIdentity`, via the existing `ApprovalValidator.validate(...)`, reused unchanged rather than reimplemented.

`ApprovalValidationReasonCode` values map directly onto `RunnerReasonCode` (`APPROVAL_NOT_FOUND`, `REPOSITORY_MISMATCH`, `COMMIT_SHA_MISMATCH`, `ENVIRONMENT_MISMATCH`, `PLAN_HASH_MISMATCH`, `APPROVAL_EXPIRED`, `APPROVAL_REVOKED`, `APPROVAL_SUPERSEDED`). `ApprovalValidationReasonCode.VALID` never reaches the mapping function (it takes the success branch instead) — the mapper throws `IllegalStateException` if ever called with `VALID`, since that would indicate a control-flow bug, not a real outcome.

`ApprovalPersistenceException` (Phase 2C-2's infrastructure-failure signal) is caught at exactly one point — around the `ApprovalValidator.validate` call — and converted to `BLOCKED` / `DURABLE_APPROVAL_STORE_UNAVAILABLE`. It is never allowed to propagate uncaught, and never silently treated as `APPROVAL_NOT_FOUND` (a genuinely different, and less alarming, condition).

## 6. Isolation Model

`RunnerWorkspaceManager` gives each `runnerRequestId` its own directory, created on first use and never reused across requests. Artifact staging reuses the same identity+atomic-write pattern as the Phase 2A execution contract's TOCTOU protection (§13 of that document) rather than inventing a second one: write to a temp file inside the workspace, then `ATOMIC_MOVE` to a content-addressed filename (`sha256-<hash>.tfplan`), then best-effort read-only permissions.

**`runnerRequestId` is treated as untrusted, opaque metadata, never as a filesystem path component.** The actual directory name is the SHA-256 hex digest of the id — a fixed-length, fixed-alphabet string (`[0-9a-f]{64}`) that cannot contain `/`, `..`, a leading `/`, or any other separator/traversal character — so a hostile id (`"../../etc"`, `"/etc/passwd"`, `".."`, an embedded separator) has no way to influence where the workspace is placed. The original id is preserved only in `RunnerEvidence.runnerRequestId()` for audit/lookup, never interpolated into a path. As defense in depth, `createWorkspace` also explicitly verifies the resolved path still starts with the configured root before creating anything, even though the hash-derived name cannot structurally escape it. `Phase2b1Tests#maliciousRunnerRequestIdsCannotEscapeWorkspaceRoot` exercises a list of hostile ids and confirms every filesystem entry created stays under the configured root.

**What Phase 2B-1 proves:** two concurrent requests never share a workspace directory or cross-contaminate staged artifacts — `Phase2b1Tests#concurrentRequestsUseIsolatedWorkspaces` runs two requests with a synchronized start barrier and asserts each workspace directory contains *only* its own artifact file, with byte-for-byte correct content, not merely that the two result objects differ.

**What Phase 2B-1 does not yet need, and does not claim:** bounded environment variables, no inherited shell environment, no user-provided `PATH`, no ambient cloud credentials — these become meaningful once a later 2B slice actually invokes a process inside the workspace. There is no process invocation surface yet to isolate, so claiming these properties now would be describing a problem this phase doesn't have rather than one it solved. Recorded as a 2B-2 item below, not silently assumed.

## 7. State Machine

```text
RECEIVED
  -> IDENTITY_RESOLVED (trusted + environment-scope checks pass)
  -> APPROVAL_RESOLVED (ApprovalValidator reports VALID)
     [VERIFY_CONTEXT ends here, at CONTEXT_VERIFIED, after toolchain checks]
  -> ARTIFACT_RESOLVED (store returns a StoredArtifact)
  -> ARTIFACT_VERIFIED (recomputed hash matches both recordedSha256 and request.planSha256, staged into workspace)
     [VERIFY_ARTIFACT ends here]
  -> CONTEXT_VERIFIED (observed Terraform version + provider-lock hash match the request's claim)
  -> READY_FOR_FUTURE_EXECUTION (PREPARE_EXECUTION only, terminal for this phase)

BLOCKED  - any check above fails; terminal
FAILED   - reserved for an unexpected internal fault distinct from a deterministic check failure (not currently reachable in Phase 2B-1's own code paths, since every failure mode here has a deterministic reason code and lands in BLOCKED)
```

No `APPLYING`/`APPLIED`/`MUTATED` state exists in `RunnerState` — there is nothing past `READY_FOR_FUTURE_EXECUTION` for this phase's code to reach, verified by `Phase2b1Tests#runnerStateHasNoMutationState`.

## 8. Reason Codes

All 17 codes specified for this phase are implemented in `RunnerReasonCode`, plus two added during review to give request-id replay/collision its own audit-distinguishable codes rather than overloading `OPERATION_NOT_ALLOWED` (which is reserved for operation authorization only): `DUPLICATE_RUNNER_REQUEST` (same id, identical content) and `RUNNER_REQUEST_FINGERPRINT_MISMATCH` (same id, different content). No generic `ERROR` value is ever used.

## 9. Evidence Model

`RunnerEvidence` is produced for every attempt — success, block, or conflict — and captures the full listed field set: identity (`runnerId`), request identity (`repository`/`commitSha`/`environment`/`planArtifactId`), expected vs. observed values for plan hash, Terraform version, and provider-lock hash, the approval validation result, final state, reason codes, and start/completion timestamps.

No field resembling raw environment variables, credentials, or secret material exists on this type — `Phase2b1Tests#runnerEvidenceHasNoEnvironmentOrSecretField` checks this structurally. Evidence is append-only in effect: once written into `ControlledRunner`'s internal ledger for a `runnerRequestId`, it is never overwritten by anything — not a duplicate attempt, not a conflicting one. `ControlledRunner.historicalEvidence(runnerRequestId)` is the dedicated, separate accessor for retrieving it, kept deliberately distinct from `execute()`'s return value so a caller can never confuse "here is what happened historically" with "this request is currently authorized."

## 10. Idempotency Semantics

**Chosen policy: block, never replay.** A resubmission of the same `runnerRequestId` is *always* `BLOCKED`, whether or not its content matches the original — it is never re-executed, and the original evidence is never returned as if it were the result of the new call:

```text
first submission of a runnerRequestId           -> processed normally
same id, byte-for-byte identical request again  -> BLOCKED / DUPLICATE_RUNNER_REQUEST
same id, DIFFERENT request content               -> BLOCKED / RUNNER_REQUEST_FINGERPRINT_MISMATCH
```

An earlier revision of this design chose cached replay (returning the original `READY_FOR_FUTURE_EXECUTION` result for an identical resubmission), reasoning that Phase 2B-1 performs no mutation so replaying a verification result carried none of the double-apply risk reject-on-repeat exists to prevent. Design review found that reasoning incomplete: **approval validity is time-varying and externally revocable** (`ApprovalRecordProducer.revoke`/`issueSuperseding`, and TTL expiry), so a resubmission's authorization state can genuinely differ from the original submission's even though the request content is byte-for-byte identical. Returning a cached `READY_FOR_FUTURE_EXECUTION` result would let a historical readiness decision silently outlive the approval it was validated against — precisely the kind of stale-authorization gap this system exists to prevent everywhere else (see the plan-hash lineage invariant in `docs/phase-2a-execution-contract.md`). Only the first `execute()` call for a given id can ever produce a non-`BLOCKED` result; every subsequent call for that id is unconditionally blocked, and the only way to see the original outcome again is the explicitly-separate `historicalEvidence()` accessor, which is never mistaken for a live authorization decision.

## 11. Concurrency Model

Each `runnerRequestId` gets its own monitor object (`ConcurrentHashMap<String, Object>`, populated via `computeIfAbsent`), and `execute()` synchronizes on that per-id monitor for its full duration. Two different ids never contend with each other and run genuinely concurrently; two callers racing on the *same* id serialize, which is what makes the cached-replay/conflict logic race-free without needing a coarser lock that would also serialize unrelated requests.

## 12. Explicit No-Mutation Boundary

- `RunnerOperation` has exactly three values, none representing mutation; `Phase2b1Tests#runnerOperationHasNoMutationValue` checks this by name (`APPLY`, `DESTROY`, `IMPORT`, `STATE_RM`, `STATE_MV`, `FORCE_UNLOCK`, `SHELL`, `EXECUTE` are all absent).
- `RunnerState` has no `APPLYING`/`APPLIED`/`MUTATED` value.
- `ControlledRunner` consumes `ApprovalProvider`, never `ApprovalAuthority` — it cannot create, revoke, or supersede an approval.
- No cloud credential type, AWS/Azure/GCP SDK call, or Terraform process invocation exists anywhere in this package.

## 13. Deferred 2B-2 Items

Recorded explicitly, not silently assumed solved:

- Real runner identity attestation (OIDC workload identity) replacing `StaticRunnerIdentityProvider`.
- A real artifact registry/store replacing `InMemoryRunnerArtifactStore` (analogous to Phase 2C-2's move from in-memory to durable approval storage).
- Per-artifact provider-lock-hash resolution (inspecting an actual bundled `.terraform.lock.hcl`) rather than a single runner-global observed value; actually invoking `terraform version` rather than a static toolchain context.
- Process-level isolation properties (bounded environment variables, no inherited shell environment, no ambient cloud credentials, ephemeral compute) — meaningful once a process is actually invoked inside a workspace.
- Container/process sandboxing for the workspace itself, if the eventual runner host warrants it.
- The actual `PREPARE_EXECUTION -> APPLY` transition, which remains out of scope for all of Phase 2B and is Phase 2A runtime's own gate, not this document's to open.
