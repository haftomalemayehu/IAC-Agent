# Phase 2A Execution Contract

**Status:** Documentation only. Defines the implementation-grade machine contract for Phase 2A. No executor, runner, or Terraform-execution code exists yet.

**Upstream binding requirements:** `docs/roadmap-phase-2.md` §3 (Phase 2A) and §1 (Plan-Hash Lineage invariant) are binding on this document. `docs/Master-Prompt.txt` §3 (Agent Contract), §28 (Forbidden Autonomous Commands), and the Authority Hierarchy (§4) remain in force unchanged. Where anything here appears to conflict with those, the more restrictive statement governs.

**Scope of this document:** the machine contract only — types, verification order, state machine, command construction, and evidence format. It does not select a runner (Phase 2B), does not define the human approval UX (Phase 2C), and does not implement anything.

---

## 1. Execution Identity vs. Request Identity

This is resolved here, not deferred, because everything else in this contract depends on it.

**Execution Identity** is the tuple that identifies *the infrastructure change being authorized*:

```text
ExecutionIdentity = (repository, commitSha, environment, planSha256)
```

Two execution requests with the same `ExecutionIdentity` are requests to make the *same* change. The system's exactly-once guarantee (§10) is defined in terms of `ExecutionIdentity`, not `requestId`.

**Request Identity** (`requestId`) identifies *an attempt* — a specific workflow run, retry, or invocation asking the system to execute a given `ExecutionIdentity`. It exists for traceability, deduplication of accidental retries, and evidence correlation. It is not authorization and does not participate in the identity of the infrastructure change itself.

**Consequence:** a retry of a failed attempt with a new `requestId` but the same `ExecutionIdentity` is still subject to every precondition in §6, including whatever exactly-once/idempotency rule applies to that identity (§10). A new `requestId` never grants a fresh chance to bypass a check that the identity has already failed or already consumed.

---

## 2. Typed Execution-Request Contract

```json
{
  "requestId": "req-123",
  "repository": "owner/repository",
  "commitSha": "40-char-git-sha",
  "environment": "nonprod",
  "planArtifactId": "artifact-456",
  "planSha256": "sha256:...",
  "terraformVersion": "1.6.6",
  "providerLockHash": "sha256:...",
  "approvalId": "approval-789",
  "requestedAt": "2026-09-11T00:05:00Z",
  "requestedBy": "system-or-principal-id"
}
```

**Binding rule — approval fields are never carried in the request:** the execution request carries `approvalId` and nothing else approval-related. It is a reference, not a claim. The request does not, and must not, carry `approvedBy`, `approvedPlanSha256`, `approvedEnvironment`, `expiresAt`, `revoked`, or any other approval attribute — not even for convenience or logging. This is enforced by the schema shape itself, not by a policy telling the executor to ignore fields that happen to be present:

```text
ExecutionRequest
    |
    | approvalId (reference only)
    v
Executor
    |
    v
Authoritative ApprovalProvider
    |
    +--> independently retrieves and verifies the ApprovalRecord (see §4)
```

**Approval attributes used for authorization MUST originate from an authoritative approval provider or cryptographically verifiable approval artifact. Caller-supplied `approvedBy`, hashes, timestamps, environment, or approval state are informational only and MUST NOT satisfy execution preconditions.** If a caller-supplied approval field is ever present anywhere in a request payload (e.g., because a caller ignored this contract), the executor must not read it — the only approval data any precondition check may consume is what `ApprovalProvider.resolve(approvalId)` independently returns. This is what prevents a compromised or careless caller from submitting `{"approvedBy": "platform-admin", "approvedPlanSha256": "<desired hash>"}` and having it treated as evidence of anything.

Field notes:

- `planArtifactId` is a **locator**, not an identity. It says where to find the artifact. `planSha256` is the identity — see §5. The two are never treated as interchangeable; `planArtifactId` alone must never satisfy a precondition.
- `requestedBy` is informational/audit only. It is never treated as an approval or as a substitute for the authoritative `ApprovalRecord.approvedBy` (§4).
- All timestamps are UTC, ISO-8601. A clock-skew tolerance is **not** defined by this contract for `expiresAt` comparison — see §6 check 9 and §14 (open question).

This request object is constructed entirely by deterministic upstream code (the same code that produced the PR review in Phase 1E). No field is ever populated from unstructured LLM output. If a future implementation needs the LLM to *propose* a `requestId` or trigger the request's creation, the proposal must pass through the exact same deterministic construction path as any other request — the LLM never writes directly into this structure, and it never writes into the approval record under any circumstance (that record is produced exclusively by Phase 2C's authoritative human-approval workflow, or, in Phase 2A, its deterministic test fixture).

---

## 3. Typed Execution-Result Contract

```json
{
  "requestId": "req-123",
  "executionIdentity": {
    "repository": "owner/repository",
    "commitSha": "40-char-git-sha",
    "environment": "nonprod",
    "planSha256": "sha256:..."
  },
  "state": "APPLY_SUCCEEDED",
  "reasonCode": null,
  "startedAt": "2026-09-11T00:05:03Z",
  "completedAt": "2026-09-11T00:06:41Z",
  "runnerIdentity": "runner-fingerprint-or-id",
  "commandInvoked": "terraform apply <content-addressed-artifact-path>",
  "terraformExitCode": 0,
  "mutationEvidence": {
    "resourceEventsObserved": true,
    "lastObservedEvent": "apply_complete",
    "streamComplete": true
  },
  "evidenceRef": ".agent/sessions/req-123/execution-evidence.json"
}
```

- `reasonCode` is `null` only when `state` is `APPLY_SUCCEEDED`, `EVIDENCE_RECORDED`, or `COMPLETED`. Every `BLOCKED`, `APPLY_FAILED`, and `PARTIALLY_APPLIED` result carries exactly one `reasonCode` from the enumerations in §9.
- `mutationEvidence` is what §11 uses to decide `APPLY_FAILED` vs. `PARTIALLY_APPLIED`. It is derived from Terraform's own structured output, never inferred or estimated.
- The result contract is written once execution reaches a terminal or blocked state and is never mutated afterward — see §12 (Evidence/Audit Contract) for immutability requirements.

---

## 4. Approval-Record Contract (shared with Phase 2C)

This is the contract Phase 2A consumes and Phase 2C is responsible for producing via an authoritative human-approval workflow. Phase 2A must not depend on *how* the record was produced, only on its shape and the guarantees below.

```json
{
  "approvalId": "approval-789",
  "approvedPlanSha256": "sha256:...",
  "approvedCommitSha": "40-char-git-sha",
  "approvedRepository": "owner/repository",
  "approvedEnvironment": "nonprod",
  "approvedBy": "principal-id",
  "approvedAt": "2026-09-11T00:00:00Z",
  "expiresAt": "2026-09-11T04:00:00Z",
  "revoked": false,
  "revokedAt": null,
  "revokedBy": null,
  "supersededBy": null
}
```

**Guarantees Phase 2A requires from whatever produces this record (Phase 2C, or a Phase 2A-only fixture provider per §14):**

1. `approvedBy` identifies a specific, authenticated human principal — never a service account, never "the system," never inferred from commit authorship.
2. The record is immutable once created, except for the `revoked`/`revokedAt`/`revokedBy` and `supersededBy` fields, which may only transition from unset to set, never back.
3. A new plan hash for the same `(repository, commitSha, environment)` **automatically** sets `supersededBy` on any prior approval for that tuple — this is the mechanism that makes "approval invalidated by a new plan" true by construction rather than by a check someone might forget to add. This automatic-supersession rule is itself part of the shared contract, not an implementation detail Phase 2C is free to omit.
4. `approvedPlanSha256`, `approvedCommitSha`, and `approvedEnvironment` are set once at creation and are never editable. If any of them need to change, that is a new approval record with a new `approvalId`, not a mutation.

**Relationship to the Phase 1E stale-hash mechanism (binding, per roadmap §1):** the informational "this review supersedes a stale prior review" note already implemented in `PullRequestReview.markdown(ciRunUrl, priorPlanHash)` and `scripts/render_pr_review.py` is the direct conceptual precursor to guarantee 3 above. Phase 2C's implementation must reuse the same plan-hash comparison logic (conceptually — not necessarily the same code, since one renders a PR comment and the other governs a binding approval record) rather than inventing a second comparison. A future implementer who finds themselves writing a second "is this hash stale" function has diverged from this contract.

### `ApprovalProvider` — the only source of approval truth

`ApprovalProvider.resolve(approvalId) -> ApprovalRecord | NotFound` is the single component authorized to produce an `ApprovalRecord` for `ApprovalValidator` to check against. Its defining property is independence from the caller:

- It does not accept, and has no parameter for, any approval attribute supplied by the execution request. The request contributes only the `approvalId` string used as a lookup key.
- In Phase 2A, this is a deterministic, test-only fixture provider — a fixed, pre-seeded store of `ApprovalRecord`s that Phase 2A's acceptance tests populate directly, never derived from or influenced by an execution request.
- In Phase 2C, this becomes the authoritative provider backed by the real human-approval workflow (GitHub Environment protection or an HCP Terraform approval gate, per roadmap §5). The consumer boundary defined here — `ApprovalProvider.resolve(approvalId) -> ApprovalRecord` — does not change when that swap happens; only the implementation behind it does.
- Whatever backs it, resolution must be independently verifiable: either a direct, trusted lookup against the approval store of record, or verification of a cryptographic signature over the `ApprovalRecord` if the provider is ever backed by a portable/signed artifact rather than a live lookup. A caller cannot influence the result by shaping its request differently.

`ApprovalValidator` (§6, checks 7-9 and 13) operates exclusively on the `ApprovalRecord` returned by `ApprovalProvider`. It never reads an approval field from the `ExecutionRequest`, because — per §2 — no such field exists on that contract.

---

## 5. Immutable Saved-Plan Artifact Identity & SHA-256 Verification

The artifact's **identity** is `planSha256` — the SHA-256 of the exact saved-plan binary produced by `terraform plan -out=<path>` and reviewed in Phase 1B/1D/1E. `planArtifactId` is only ever a locator used to *find* bytes; it carries no authority.

**Verification procedure (`ArtifactVerifier`):**

1. Resolve `planArtifactId` to a byte stream via the artifact store (in Phase 2A: a local, single-writer directory populated once per request — see §13 open questions for the Phase 2B evolution of this).
2. Read the full artifact into memory (or a content-addressed on-disk copy — see §13, TOCTOU protection) and compute SHA-256 over the exact bytes read.
3. Compare the computed hash, byte-for-byte as a hex string with the `sha256:` prefix, against `planSha256` from the execution request.
4. On any mismatch: `BLOCKED`, reason `PLAN_HASH_MISMATCH`. This check does not distinguish "tampered," "wrong artifact," or "corrupted" — all three collapse to the same reason code and the same blocked state, because the enforcement action is identical regardless of cause.
5. On match: the verified bytes (not the original mutable path) are what proceeds to §13's content-addressed staging step. Nothing downstream re-reads the original `planArtifactId` location.

**Never trusted as identity:** artifact filename, artifact upload timestamp, artifact size, `planArtifactId` string equality, or any metadata field not cryptographically derived from the artifact's own bytes.

---

## 6. Mandatory Pre-Execution Revalidation — Enforcement Mapping

Every check from roadmap §3 is mapped here to a concrete component, input, and reason code. This mapping is what makes runtime acceptance criteria implementable rather than aspirational.

| # | Check | Component | Reason code on failure |
|---|---|---|---|
| 1 | request ID valid, not already completed | `IdempotencyGuard` | `REQUEST_ALREADY_COMPLETED` |
| 2 | repository identity matches reviewed repository | `IdentityValidator` | `REPOSITORY_MISMATCH` |
| 3 | commit SHA matches approved commit | `IdentityValidator` | `COMMIT_MISMATCH` |
| 4 | environment matches approved environment | `IdentityValidator` | `ENVIRONMENT_MISMATCH` |
| 5 | saved-plan artifact exists and is the expected artifact | `ArtifactVerifier` | `ARTIFACT_NOT_FOUND` |
| 6 | recomputed SHA-256 matches `planSha256` | `ArtifactVerifier` | `PLAN_HASH_MISMATCH` |
| 7 | the `ApprovalRecord` independently resolved via `ApprovalProvider.resolve(approvalId)` (§4) references the exact same plan SHA-256 | `ApprovalValidator` | `APPROVAL_PLAN_HASH_MISMATCH` |
| 8 | the resolved `ApprovalRecord` references the exact same commit SHA and environment | `ApprovalValidator` | `APPROVAL_CONTEXT_MISMATCH` |
| 9 | the resolved `ApprovalRecord` is valid — not expired/revoked/superseded | `ApprovalValidator` | `APPROVAL_EXPIRED` / `APPROVAL_REVOKED` / `APPROVAL_SUPERSEDED` (distinct codes — see below) |
| 10 | provider lockfile hash matches reviewed context | `ContextValidator` | `PROVIDER_LOCK_MISMATCH` |
| 11 | Terraform version matches permitted execution version | `ContextValidator` | `TERRAFORM_VERSION_MISMATCH` |
| 12 | all mandatory upstream gates remain PASS | `GateStatusValidator` | `UPSTREAM_GATE_NOT_PASS` |
| 13 | no newer plan has superseded the approved plan | `ApprovalValidator` (via the resolved record's `supersededBy`) | `APPROVAL_SUPERSEDED` |
| 14 | runner identity is authorized for target environment | `RunnerAuthorizer` | `RUNNER_UNAUTHORIZED` |
| 15 | execution command resolves exactly to the allowlisted saved-plan apply operation | `CommandBuilder` | `COMMAND_NOT_ALLOWED` |

Checks 7-9 and 13 read only from the `ApprovalRecord` that `ApprovalProvider` independently resolved — never from the `ExecutionRequest`, which (§2) carries no approval attributes at all beyond the `approvalId` lookup key. This is what makes the "approval authenticity" guarantee structural rather than a rule the implementer has to remember.

Checks 9 and 13 both touch approval validity but are kept as distinct reason codes (`APPROVAL_EXPIRED`, `APPROVAL_REVOKED`, `APPROVAL_SUPERSEDED`) rather than one generic `APPROVAL_INVALID`, because the evidence record must let a human immediately distinguish "this approval timed out" from "someone revoked it" from "a newer plan replaced it" without reading logs.

**Ordering:** checks run in the numeric order above. The first failing check determines the reason code; evaluation stops there (no need to reveal the full set of problems with a request that is already blocked on check 2, and stopping early avoids doing artifact I/O or approval lookups for a request that has already failed identity checks). All 15 checks must be re-run in full for every execution attempt — none may be cached or skipped based on a prior attempt's result, because a prior attempt's result describes a different point in time.

**Failure handling:** every failure is `BLOCKED` with the mapped reason code. No precondition failure is ever downgraded to a warning, retried automatically, or bypassed by any field in the execution request — including any field that originated from or was influenced by LLM output.

---

## 7. Command Allowlist & Safe Command Construction

The executor exposes exactly one operation:

```text
applySavedPlan(verifiedArtifactPath: Path) -> ExecutionOutcome
```

This is a typed function, not a shell or command-string interface. Internally, and only internally, it invokes:

```text
terraform apply <verifiedArtifactPath>
```

using direct process invocation with an argument vector (`["terraform", "apply", verifiedArtifactPath.toString()]`), never a shell string that could be subject to injection. `verifiedArtifactPath` is supplied **only** by `ArtifactVerifier`'s content-addressed staging output (§13) — it is never accepted as a parameter from the execution request, from configuration, or from any LLM-influenced value. There is no code path by which a caller can supply an arbitrary path, an arbitrary Terraform subcommand, or an arbitrary shell command to this function.

This is what makes `COMMAND_NOT_ALLOWED` (check 15) effectively unreachable in normal operation and reachable only if something upstream attempted to call the executor with a request shape it doesn't recognize — which is itself evidence of a bug or attack to record, not a normal blocked outcome.

No other Terraform subcommand, and no shell command, is reachable through this component under any input. `terraform destroy`, `terraform import`, `terraform state rm/mv`, `terraform force-unlock`, and `terraform apply` without a saved-plan argument have no corresponding code path — they are absent, not merely rejected at runtime.

---

## 8. Idempotency and Replay Prevention

**Decision:** Phase 2A uses **exactly-once, reject-on-repeat** semantics, keyed on `ExecutionIdentity` (§1), not on `requestId` — enforced through an **atomic claim**, not a check-then-act lookup.

**Why a lookup alone is insufficient:** a plain "look up whether this identity has already executed, then proceed if not" is a classic time-of-check-to-time-of-use race. Two requests for the same `ExecutionIdentity` arriving concurrently can both observe "not yet executed" before either has recorded that it is proceeding:

```text
Request A: lookup -> not executed
Request B: lookup -> not executed

A -> APPLYING
B -> APPLYING          (both passed the check before either persisted anything)
```

Both would then be authorized to apply the same plan. That is a real defect in a design that only ever "rejects if already completed" — it does not, by itself, guarantee single execution.

**The fix — an atomic claim, evaluated as its own state:**

```text
claimExecution(identity, requestId)

  SUCCESS          -> this request now exclusively owns execution of this identity
  ALREADY_CLAIMED   -> another request currently owns it (in-flight, non-terminal)
  ALREADY_COMPLETED -> a prior request already reached APPLY_SUCCEEDED for it
  AMBIGUOUS         -> a claim record exists in an indeterminate state (see below)
```

`claimExecution` must be backed by a genuine compare-and-set / uniqueness-constraint operation against the identity — an insert-if-absent or equivalent transaction, not a separate read followed by a separate write. Exactly one caller can ever transition a given `ExecutionIdentity` from unclaimed to claimed; every other concurrent caller receives `ALREADY_CLAIMED` from the same atomic operation, never from a subsequent lookup.

This claim is evaluated in its own state, `EXECUTION_CLAIMED`, positioned between `PRECONDITION_CHECK` and `READY` (§10) — **after** all 15 checks in §6 have passed (so an unauthorized or malformed request is never able to occupy the claim slot at all), and **before** Terraform is invoked (so the claim, not the `terraform apply` call itself, is the actual mutual-exclusion boundary).

**Outcomes:**

- `SUCCESS` → proceeds to `READY`, then `APPLYING`.
- `ALREADY_CLAIMED` → `BLOCKED`, reason `EXECUTION_IDENTITY_ALREADY_CLAIMED`. The losing request(s) are not queued or retried automatically; a caller that wants the change applied must submit a new attempt after the in-flight one resolves.
- `ALREADY_COMPLETED` → `BLOCKED`, reason `EXECUTION_IDENTITY_ALREADY_CONSUMED`. The caller must obtain a new plan and a new approval for any further change — re-running the exact same approved plan against infrastructure that has already received it is not treated as a safe no-op by this contract, because Terraform's own idempotency is not a guarantee this system re-verifies before a second apply.
- `AMBIGUOUS` → `BLOCKED`, reason `EXECUTION_CLAIM_AMBIGUOUS`. This is the case where a claim record exists showing a prior attempt reached `APPLYING` (or `EXECUTION_CLAIMED`) but never recorded a terminal outcome — e.g., the process crashed or the claim store itself lost the completion write. **A crashed or ambiguous claim must never be automatically cleared or retried.** Resolving an `AMBIGUOUS` claim requires explicit operator intervention (inspecting actual infrastructure/state to determine what, if anything, happened) before any further attempt against that identity can proceed — the same operator-intervention requirement as `PARTIALLY_APPLIED` (§11), because an ambiguous claim and a partially-applied execution are the same category of problem: the system cannot prove what happened, so it must not guess.

If the prior attempt for this identity ended cleanly in `BLOCKED` (at either the precondition-check stage or the claim stage) or in `APPLY_FAILED` with no mutation evidence (§11): a new attempt with a new `requestId` is permitted and re-runs all 15 checks and a fresh claim attempt from scratch. If the prior attempt ended in `PARTIALLY_APPLIED` or `AMBIGUOUS`: **no automatic new attempt is permitted**, full stop.

**Why reject rather than safe-replay:** a "return the cached prior success" design would need its own correctness argument (what if the infrastructure has drifted since?) that Phase 2A does not yet have the tooling (Phase 2D verification, Phase 2E drift detection) to support. Reject-on-repeat is the simpler, safer default for this phase; a future phase may revisit this once post-apply verification exists to make cached-replay provably safe. This is a deliberate scope boundary, not an oversight — see §14.

---

## 9. Reason Code Enumeration

**`BLOCKED` reason codes** (exhaustive as of this document; adding one requires updating this table):

```text
REQUEST_ALREADY_COMPLETED
EXECUTION_IDENTITY_ALREADY_CONSUMED
EXECUTION_IDENTITY_ALREADY_CLAIMED
EXECUTION_CLAIM_AMBIGUOUS
REPOSITORY_MISMATCH
COMMIT_MISMATCH
ENVIRONMENT_MISMATCH
ARTIFACT_NOT_FOUND
PLAN_HASH_MISMATCH
APPROVAL_PLAN_HASH_MISMATCH
APPROVAL_CONTEXT_MISMATCH
APPROVAL_EXPIRED
APPROVAL_REVOKED
APPROVAL_SUPERSEDED
PROVIDER_LOCK_MISMATCH
TERRAFORM_VERSION_MISMATCH
UPSTREAM_GATE_NOT_PASS
RUNNER_UNAUTHORIZED
RUNNER_UNAVAILABLE
COMMAND_NOT_ALLOWED
```

**`APPLY_FAILED` reason codes** (Terraform ran, structured output confirms no mutation began — see §11):

```text
APPLY_PRECHECK_FAILED
PROVIDER_AUTH_FAILED_PRE_MUTATION
STATE_LOCK_CONTENTION
```

**`PARTIALLY_APPLIED` reason codes** (mutation may have begun, or the outcome cannot be proven otherwise — see §11):

```text
MUTATION_STARTED_THEN_FAILED
RUNNER_TERMINATED_DURING_APPLY
STRUCTURED_OUTPUT_INCOMPLETE
```

`RUNNER_UNAVAILABLE` is `BLOCKED`, not `APPLY_FAILED`, because it means Terraform was never invoked — there is no ambiguity about mutation to preserve. `STATE_LOCK_CONTENTION` is `APPLY_FAILED` because a lock rejection happens before any resource mutation can occur, by Terraform's own locking design — but see §14 for the residual assumption this rests on.

---

## 10. Execution State Machine

```text
REQUESTED
   │
   ▼
PRECONDITION_CHECK ──(any of 15 checks fails)──▶ BLOCKED  [terminal]
   │
   ▼ (all 15 checks pass)
EXECUTION_CLAIMED ──(claimExecution() returns ALREADY_CLAIMED / ALREADY_COMPLETED / AMBIGUOUS)──▶ BLOCKED  [terminal]
   │
   ▼ (claimExecution() returns SUCCESS)
READY
   │
   ▼
APPLYING
   │
   ├──(terraform exits 0, structured output complete and clean)──▶ APPLY_SUCCEEDED
   │
   ├──(Terraform execution definitively failed before any possible mutation began)──▶ APPLY_FAILED  [terminal]
   │
   └──(mutation observed, OR the executor cannot prove mutation did not begin)──▶ PARTIALLY_APPLIED  [terminal, requires operator intervention]

APPLY_SUCCEEDED
   │
   ▼
EVIDENCE_RECORDED
   │
   ▼
COMPLETED  [terminal]
```

**Legal transitions only** — no other transition exists:

| From | To | Condition |
|---|---|---|
| `REQUESTED` | `PRECONDITION_CHECK` | automatic, immediately |
| `PRECONDITION_CHECK` | `BLOCKED` | any of the 15 checks fails |
| `PRECONDITION_CHECK` | `EXECUTION_CLAIMED` | all 15 checks pass |
| `EXECUTION_CLAIMED` | `BLOCKED` | `claimExecution(identity, requestId)` (§8) returns `ALREADY_CLAIMED`, `ALREADY_COMPLETED`, or `AMBIGUOUS` |
| `EXECUTION_CLAIMED` | `READY` | `claimExecution(identity, requestId)` returns `SUCCESS` |
| `READY` | `APPLYING` | executor invokes `terraform apply <verifiedArtifactPath>` |
| `APPLYING` | `APPLY_SUCCEEDED` | exit 0 and structured output stream is complete |
| `APPLYING` | `APPLY_FAILED` | Terraform execution definitively failed before any possible mutation began (§11) |
| `APPLYING` | `PARTIALLY_APPLIED` | mutation observed, or the executor cannot prove mutation did not begin (§11) |
| `APPLY_SUCCEEDED` | `EVIDENCE_RECORDED` | automatic, immediately |
| `EVIDENCE_RECORDED` | `COMPLETED` | automatic, immediately |

`BLOCKED`, `APPLY_FAILED`, and `PARTIALLY_APPLIED` are terminal for the given `requestId`. `PARTIALLY_APPLIED`, and an `EXECUTION_CLAIMED → BLOCKED` transition with reason `EXECUTION_CLAIM_AMBIGUOUS`, additionally block all future `requestId`s for the same `ExecutionIdentity` per §8, until explicit non-automated operator intervention. There is no automatic transition out of either state — automatic retry from an ambiguous state is explicitly forbidden by roadmap §3 and repeated here as a hard rule: **no code path may transition a `PARTIALLY_APPLIED` execution, or an identity with an `AMBIGUOUS` claim, back to `EXECUTION_CLAIMED`, `READY`, or `APPLYING`.**

The `EXECUTION_CLAIMED` state exists specifically to make the mutual-exclusion boundary an explicit, auditable state transition rather than an implicit property of "we checked and it looked free" — see §8 for why a plain lookup is insufficient.

---

## 11. The `BLOCKED` / `APPLY_FAILED` / `PARTIALLY_APPLIED` Boundary

Four states, defined precisely:

```text
BLOCKED
    Preconditions fail before execution authority is exercised —
    including the case where Terraform is never even invoked.

APPLY_FAILED
    Terraform execution definitively failed before any possible
    mutation began.

PARTIALLY_APPLIED
    Mutation was observed, OR the executor cannot prove that
    mutation did not begin.

APPLY_SUCCEEDED
    Terraform reports successful apply and the expected completion
    evidence is intact.
```

This is resolved concretely using Terraform's own structured output (`terraform apply -json`), which streams one JSON event per significant action, including `apply_start` / `apply_complete` / `apply_errored` events per resource.

**Decision rule (`OutcomeClassifier`), evaluated in this order:**

1. **`BLOCKED`, not `APPLY_FAILED` or `PARTIALLY_APPLIED`:** if the executor could not even launch the `terraform apply` process at all (binary missing, runner failure before invocation) — `RUNNER_UNAVAILABLE`. No execution authority was exercised; there is categorically nothing to be "partial" about. This check is evaluated first and is mutually exclusive with every rule below — a process that never started can never satisfy any of the mutation-evidence conditions in rules 2-4, by definition, so there is no ambiguity between "never launched" and "launched but produced no output" left for those rules to resolve.
2. **`APPLY_FAILED`:** the process launched, Terraform's execution authority *was* exercised, and the structured JSON stream is fully captured through to a terminal event, **and that complete stream proves zero `apply_start` events for any resource occurred** before the terminal event. The reason code further distinguishes pre-check failure (`APPLY_PRECHECK_FAILED`), a provider auth failure before any resource action (`PROVIDER_AUTH_FAILED_PRE_MUTATION`), or a state lock rejection (`STATE_LOCK_CONTENTION`) — all three occur, by Terraform's own design, before any resource mutation begins, and the stream that shows this is itself complete and conclusive.
3. **`PARTIALLY_APPLIED`:** the process launched and **any** `apply_start` event for any resource appears in the stream before failure, regardless of how many resources or whether that specific resource's `apply_complete` ever arrived — `MUTATION_STARTED_THEN_FAILED`.
4. **`PARTIALLY_APPLIED`:** the process launched (execution authority *was* exercised) but the structured output stream ends abruptly or is otherwise incomplete — connection lost, runner terminated, process killed, log truncated — such that the executor cannot conclusively prove rule 2's "zero mutation events" condition. Reason code `RUNNER_TERMINATED_DURING_APPLY` if runner loss is directly observed, else `STRUCTURED_OUTPUT_INCOMPLETE`. **Runner interruption or loss after Terraform execution begins is `PARTIALLY_APPLIED` unless deterministic evidence proves no mutation could have started** — and per rule 2, proving that requires a *complete* stream showing zero `apply_start` events, not merely the absence of a stream. **Absence of evidence of mutation is never treated as evidence of absence of mutation.**

The critical distinction from rule 1: rule 1 fires only when the process itself never ran, which is unambiguous and requires no evidence-quality judgment. Rules 2-4 only apply once it's established that Terraform's execution authority was actually exercised — at that point, and only at that point, does the conservative "cannot prove absence of mutation ⇒ `PARTIALLY_APPLIED`" principle take over. A binary that fails to launch is not a partial infrastructure deployment; it is a request that never reached the point of being able to deploy anything.

This directly implements the roadmap §3 rule: *"If Terraform exits unsuccessfully after mutation may have begun, the system must conservatively treat the outcome as potentially partial until state and execution evidence establish otherwise."*

---

## 12. Evidence / Audit Contract

Every execution attempt, regardless of outcome, produces exactly one evidence record, written once and never mutated:

```json
{
  "requestId": "req-123",
  "executionIdentity": {
    "repository": "owner/repository",
    "commitSha": "40-char-git-sha",
    "environment": "nonprod",
    "planSha256": "sha256:..."
  },
  "approvalId": "approval-789",
  "runnerIdentity": "runner-fingerprint-or-id",
  "commandInvoked": "terraform apply <path>",
  "preconditionResults": [
    {"check": "REQUEST_ID_VALID", "result": "PASS"},
    {"check": "REPOSITORY_MATCH", "result": "PASS"},
    "... one entry per check in §6, in order, for every attempt, including blocked ones ..."
  ],
  "finalState": "APPLY_SUCCEEDED",
  "reasonCode": null,
  "terraformExitCode": 0,
  "mutationEvidence": { "resourceEventsObserved": true, "streamComplete": true },
  "startedAt": "2026-09-11T00:05:03Z",
  "completedAt": "2026-09-11T00:06:41Z",
  "evidenceSchemaVersion": "1"
}
```

**Requirements:**

- Written for `BLOCKED` outcomes too — a blocked attempt is exactly as auditable as a successful one, and often more security-relevant.
- `preconditionResults` records every check from §6 that was evaluated before the terminal result (per the stop-on-first-failure rule in §6, this is a prefix of the full 15, ending at whichever check failed, or all 15 if none failed).
- Stored under the existing session-evidence convention (`.agent/sessions/<requestId>/...`), consistent with Phase 1's `ArtifactSessionManager` pattern — this contract does not introduce a second evidence storage mechanism.
- Immutable once written. Any correction or follow-up (e.g., an operator's manual resolution of a `PARTIALLY_APPLIED` state) is a **new**, separately timestamped record referencing the original `requestId`, never an edit to the original.
- Never contains credential material, per `Master-Prompt.txt` §34 and the Phase 2A Security/Trust Boundary (roadmap §3) — this is enforced by the same redaction discipline Phase 2F will formalize, not deferred entirely to Phase 2F.

---

## 13. TOCTOU Protection Between Verification and Execution

The threat: `ArtifactVerifier` reads and hashes an artifact at time T1; `terraform apply` reads the "same" path at time T2; if anything can alter the bytes at that path between T1 and T2, hash verification is meaningless.

**Clarification on what hash-naming and atomic writes actually buy you:** a content-addressed path and an atomic write establish artifact *identity* — they guarantee that if a file exists at `sha256-<hash>.tfplan`, its content matches that hash at the moment it was written. They do not, by themselves, create *immutability* — nothing in "name the file after its hash" prevents a later write to the same path (whether an overwrite, a delete-and-recreate, or a bind-mount swap) from a process that has write access to that directory. Immutability is a property of the storage/filesystem permissions layered on top, not of the naming scheme. This document treats those as two distinct guarantees and does not conflate them.

**Design (Phase 2A scope — single-runner, single-job execution):**

```text
download
  ↓
verify hash
  ↓
atomic stage under content-derived identity
  ↓
prevent ordinary mutation/replacement (read-only permissions, single-writer directory)
  ↓
final hash verification (immediately before exec)
  ↓
immediate exec
```

1. `ArtifactVerifier` reads the artifact's full bytes into memory once, computes SHA-256 over those exact bytes, and — only on a successful hash match — writes those exact bytes to a **new, content-addressed path**: `<staging-dir>/sha256-<hash>.tfplan`, using write-to-temp-file-then-atomic-rename (never write-in-place), so the file at the content-addressed path either doesn't exist yet or is fully and correctly written — there is no partially-written state visible at that path.
2. The content-addressed path is opened **read-only** by the process that will invoke `terraform apply`, and the filesystem permissions on the staging directory are set so that only the verifying process (not any concurrent job, not any LLM-invoked tool) can write to it. This is the "prevent ordinary mutation/replacement" step above: the staged artifact is made read-only and non-replaceable to the execution process **to the extent the Phase 2A runner's filesystem permission model actually supports** — a plain file-permission bit, not a hardware- or kernel-enforced immutability guarantee. Stronger runtime isolation (dedicated read-only mounts, a runner platform's own immutable-artifact primitives) is explicitly deferred to Phase 2B, and this document does not claim Phase 2A achieves more than ordinary filesystem permissions provide.
3. Immediately before invoking the `terraform apply` subprocess — as the literal last statement before `exec`, not "close to it" — `ArtifactVerifier`'s hash routine is invoked a second time against the content-addressed path. This is redundant with step 1 by design: it exists specifically to catch any tampering that occurred in the (hopefully near-zero) window between staging and exec, including bugs in this very system. A mismatch at this point is `BLOCKED`, `PLAN_HASH_MISMATCH` — the same reason code as the original check, because from an evidence-consumer's perspective it is the same failure mode, just caught one step later.
4. The runner executing a given request must be a single-tenant, ephemeral execution context for the duration of that request (this is a requirement this contract places on Phase 2B's runner design, not something 2A can itself guarantee without 2B) — no other job, human session, or process shares the staging directory or filesystem namespace during the window between verification and apply.
5. Phase 2A's own scope is limited to a minimal/local runner (per roadmap §3 dependencies) where guarantee 4 is achieved by simply not running concurrent jobs against the same staging directory, enforced by the `IdempotencyGuard`'s "no concurrent execution for the same identity" rule (§8). This is a real but narrower guarantee than Phase 2B's eventual ephemeral-isolated-runner design will provide, and is called out explicitly rather than silently assumed — see §14.

**What this does not (yet) protect against:** a compromised or malicious *runner host itself* (as opposed to a concurrent job on a shared host) could still tamper with its own filesystem between steps 3 and the actual `exec()` syscall — no userspace re-hash check can fully close a gap at that level. Full protection against a compromised runner requires runner attestation and/or immutable, versioned, externally-verified artifact storage (object storage with object-lock, or the runner platform's own artifact integrity guarantees), which is explicitly Phase 2B's responsibility. Phase 2A's re-hash-immediately-before-exec step is a real, meaningful mitigation against races and bugs, not a complete defense against a fully compromised runner — the residual risk is recorded, not hidden, in `docs/phase-2a-threat-model.md`.

---

## 14. Open Design Questions / Explicit Phase 2A-Scoped Simplifications

These are decisions made for Phase 2A specifically, with a stated reason, rather than left silently ambiguous. Each is expected to be revisited, not silently inherited, when the referenced later phase is designed.

1. **Clock-skew tolerance for `expiresAt` comparison** (§2, §6 check 9) is not defined here. Recommendation for whoever implements: use the runner's own trusted clock, no grace period, and treat any clock-sync failure on the runner itself as `RUNNER_UNAVAILABLE` rather than silently comparing against a potentially-wrong clock. Not resolved further in this document because it depends on the concrete runner chosen in Phase 2B.
2. **Approval revocation mechanism** (§4 guarantee 2): this document defines the *shape* (`revoked`/`revokedAt`/`revokedBy`) but not *how* revocation is triggered or by whom, since that is a Phase 2C UX question. Phase 2A's own acceptance testing (roadmap §3) may use a static fixture/test approval provider that sets these fields directly.
3. **Runner identity mechanism** (§6 check 14): Phase 2A, lacking Phase 2B's runner, is expected to use a minimal, statically-configured allowlist of runner identifiers for its single non-production environment. This is explicitly weaker than the OIDC-based, dynamically-attested runner identity Phase 2B is expected to introduce, and must not be mistaken for that stronger guarantee when Phase 2A's acceptance results are later cited.
4. **Idempotent-replay vs. reject-on-repeat** (§8): reject-on-repeat is the Phase 2A decision. Revisiting this to allow safe cached-replay is explicitly deferred until Phase 2D (post-apply verification) exists to make "the infrastructure still matches what we last applied" a provable precondition rather than an assumption.
5. **Runner-host compromise** (§13): acknowledged residual risk for Phase 2A, expected to be substantially reduced (not necessarily eliminated) by Phase 2B's ephemeral, isolated runner design.

None of these open questions permit any relaxation of §6's 15 mandatory checks, §7's command allowlist, or §10's state machine. They are scoping notes about *how strongly* certain checks can be enforced given Phase 2A's deliberately minimal runner, not exceptions to *whether* they are enforced.
