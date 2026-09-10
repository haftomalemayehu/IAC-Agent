# Phase 2 Roadmap: Controlled Execution Authority

**Status:** Documentation baseline only. No Phase 2 runtime functionality is implemented as of this document.

**Frozen reference point:** `phase-1e-checkpoint` (tag on `main`, commit `84032e1`). Phase 1A-1E delivered a deterministic, read/plan-only safety and control foundation: repository inspection, provider-schema enforcement, format/validate/lint/security gates, real Terraform plan parsing, a risk engine, a plan-hash-bound PR review model, and hardened remote GitHub PR acceptance. See `docs/Master-Prompt.txt` for the governing specification and authority principles that remain in force.

**What Phase 2 is:** the transition from a system that reviews infrastructure changes to a system that may, under strict and narrow conditions, execute an already-reviewed-and-approved change. This is a different trust boundary than Phase 1, not an extension of it. Every sub-phase below must be read against that boundary.

**Relationship to `docs/Master-Prompt.txt`:** this document is the single detailed source of truth for Phase 2. `Master-Prompt.txt` §47-48 point here rather than maintaining a second, competing description. High-level architectural principles (authority hierarchy, anti-hallucination rule, forbidden commands, agent operating modes) remain defined in `Master-Prompt.txt` and apply unchanged to everything below.

---

## 1. The Plan-Hash Lineage (Binding Architecture Invariant)

This is not one sub-phase's concern — it is the invariant that every sub-phase below must preserve. It is what turns "an LLM suggested applying this" into "a cryptographically specific, human-approved artifact was applied, and nothing else could have been."

```text
Phase 1B
Terraform plan SHA-256
      ↓
Phase 1D / 1E
PR review bound to plan hash
      ↓
Phase 2C
Human approval bound to the same plan hash
      ↓
Phase 2A / 2B
Only that exact approved saved plan may execute
      ↓
Phase 2D
Execution result and verification recorded against that lineage
```

**The invariant, stated explicitly:**

> A plan that was not reviewed and approved by its exact cryptographic hash must never be applied. A changed commit, changed Terraform configuration, regenerated plan, changed plan hash, expired approval, or materially changed execution context must invalidate execution eligibility.

**Binding constraint on implementation:** Phase 2C MUST extend the existing Phase 1E stale-plan-hash mechanism (`PullRequestReview.markdown(ciRunUrl, priorPlanHash)` in `src/main/java/com/iacagent/iacagent/PullRequestReview.java`, and `scripts/render_pr_review.py`'s `prior_plan_hash` handling) rather than introducing an independent approval identity mechanism. Phase 1E already proved, against real GitHub PRs, that a hash mismatch can be detected and surfaced as "this supersedes a stale prior review." Phase 2C's job is to take that same primitive and make it binding — a cryptographic approval record, not just an informational comment — not to invent a second, parallel hash/identity scheme that could drift from the first.

There must only ever be one plan-hash concept in this system. If a future implementer finds themselves computing or comparing a second kind of "plan identity" anywhere in Phase 2, that is a design error to be caught in review, not a variant to be reconciled later.

---

## 2. The Eventual Execution Chain

```text
REQUEST
  ↓
DISCOVER
  ↓
AUTHOR
  ↓
SCHEMA VERIFY
  ↓
VALIDATE / LINT / SECURITY / POLICY / TEST
  ↓
PLAN
  ↓
RISK + COST
  ↓
PR REVIEW
  ↓
HUMAN APPROVAL
  ↓
APPROVAL/PLAN-HASH VERIFICATION
  ↓
CONTROLLED APPLY OF EXACT SAVED PLAN
  ↓
POST-DEPLOYMENT VERIFICATION
  ↓
AUDIT
```

**Deterministic control plane vs. LLM reasoning — drawn explicitly:**

| Stage | Authority |
|---|---|
| REQUEST → PR REVIEW | Already deterministic as of Phase 1E: provider schema, Terraform CLI, TFLint/Checkov, `terraform plan` JSON, and the risk engine are authoritative. The LLM may propose Terraform and explain results, but does not decide PASS/FAIL/BLOCKED. |
| HUMAN APPROVAL | Exclusively human. No LLM or agent process may grant, infer, or simulate approval. |
| APPROVAL/PLAN-HASH VERIFICATION | Deterministic code only: hash comparison, commit SHA comparison, environment comparison, policy-result comparison. No model inference in this step, ever. |
| CONTROLLED APPLY | Deterministic execution of a pre-existing, unmodified saved plan artifact by an authorized runner. The LLM does not construct, edit, or regenerate what gets applied. |
| POST-DEPLOYMENT VERIFICATION / AUDIT | Deterministic checks and structured recording. The LLM may summarize results for humans but does not decide whether verification passed. |

This table itself is a design constraint: every Phase 2 sub-phase's acceptance criteria must be checkable by a person asking "which row of this table does this code sit in, and does it stay there?"

---

## 3. Phase 2A — Controlled Execution Authority

### Objective

Define and implement the minimum mechanism by which an already-reviewed, explicitly approved, hash-verified Terraform saved plan may be applied in a single authorized non-production environment, with no path by which an unapproved, stale, replayed, regenerated, modified, or context-mismatched plan can reach `terraform apply`.

The binding invariant is:

**A Terraform plan may execute only if the exact saved plan artifact, its cryptographic hash, the source commit, target environment, approval record, and execution context all match the values that were reviewed and approved.**

A regenerated plan is always a new plan, even if its semantic diff appears equivalent. "Equivalent plan" must never become an escape hatch from hash verification.

### Scope
- Apply only the exact reviewed Terraform saved-plan artifact produced by `terraform plan -out=<path>` and invoke Terraform as `terraform apply <saved-plan>`. Never apply directly from configuration and never regenerate a plan during execution.
- Enforce plan-hash match between the approved record (Phase 2C's contract) and the artifact about to be applied, immediately before apply, as a hard gate.
- Phase 2A execution is enabled for exactly one designated non-production environment. The authorization model must be designed so additional environments can later receive distinct, non-overlapping execution identities and policies, but production execution is not enabled in Phase 2A.
- Require human approval for any protected action (see §12, Preliminary Phase 2A Authority Boundaries).
- Rollback and failure handling: a failed or partial apply must be detected, reported, and must not silently leave the system in an ambiguous state.
- Persist a deterministic execution record containing the approved plan identity, execution preconditions, runner identity, command invoked, timestamps, Terraform result, and final execution state.

### Explicit Non-Goals
- No remote runner selection or configuration (that is Phase 2B).
- No new approval UI/workflow (that is Phase 2C) — 2A only *consumes* an approval record conforming to a shared contract, it does not define how one is produced.
- No drift reconciliation, no post-deploy health checking beyond detecting apply failure (that is Phase 2D).
- No autonomous `destroy`, state surgery, `force-unlock`, or `import` under any condition — these remain permanently outside autonomous authority, not just outside the Phase 2A MVP.
- No production execution in Phase 2A. Production is not merely disabled by configuration; the Phase 2A acceptance environment and credentials must not possess production execution authority.
- No rollback automation that attempts to infer or reverse partially applied infrastructure. Phase 2A detects and records partial/failed execution; remediation remains a separate explicitly reviewed operation. Terraform apply is not transactional, so "rollback handling" must never be read as "automatic reversal."

### Security / Trust Boundary

Phase 2A introduces infrastructure execution authority and therefore establishes a new privilege boundary.

The LLM is permanently outside that boundary. LLM output may request, explain, or propose execution, but it cannot satisfy any execution precondition, create or modify approval state, select the executable artifact, alter the target environment, supply executable shell commands, or override deterministic policy.

Assume the LLM, repository content, Terraform input files, pull-request text, and user-provided natural language may all be malicious.

Under that assumption, a compromised or manipulated LLM must not be able to:

- cause an unapproved plan to execute;
- substitute a different plan artifact;
- replay approval against another plan or environment;
- widen execution credentials;
- bypass schema, validation, security, policy, risk, or approval gates;
- invoke Terraform commands outside the explicit execution allowlist;
- trigger production execution.

The only infrastructure mutation reachable through the Phase 2A boundary is execution of the exact saved plan that has independently satisfied every deterministic execution precondition.

The executor is therefore a narrow deterministic capability, not an LLM tool with general shell or Terraform authority. This sub-phase is the point where "a well-controlled Terraform reviewer" could become "a privileged infrastructure executor" if the authority model is wrong — the design review for this section happens before any code is written.

### Dependencies
- A reviewed approval-record contract shared with Phase 2C. Phase 2A consumes the contract; Phase 2C later supplies the user-facing approval workflow that produces conforming records.
- Phase 1B plan-hash computation (already exists).
- An execution environment/runner — even a minimal one — to actually invoke `terraform apply <saved-plan>`; full remote-runner hardening is Phase 2B, but 2A's design must not assume a runner that doesn't yet exist.

**Ordering note:** Phase 2A and Phase 2C share one approval contract but do not require circular implementation dependencies.

Before Phase 2A runtime code begins, the approval-record schema and plan-hash binding semantics must be frozen as part of the Phase 2A design review.

Phase 2A may use a deterministic test approval provider or fixture conforming to that contract for non-production acceptance.

Phase 2C later implements the authoritative human approval workflow without changing the identity semantics established here.

The roadmap taxonomy (2A, 2B, 2C, ...) is not the implementation sequence. **2A is designed first; it is not necessarily implemented first.** The actual implementation sequence is:

```text
2A-DESIGN
    ↓
shared approval contract
    ↓
2C minimal approval-record producer
    ↓
2B controlled runner
    ↓
2A runtime execution
    ↓
2A acceptance
```

### Execution Contract

Every execution request must contain, at minimum:

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
  "approval": {
    "approvalId": "approval-789",
    "approvedPlanSha256": "sha256:...",
    "approvedCommitSha": "40-char-git-sha",
    "approvedEnvironment": "nonprod",
    "approvedBy": "principal-id",
    "approvedAt": "timestamp",
    "expiresAt": "timestamp"
  }
}
```

The exact schema may evolve during implementation, but these identity bindings are mandatory. The execution request is not authorization by itself. Authorization exists only when every deterministic precondition below succeeds.

### Mandatory Pre-Execution Revalidation

Immediately before invoking Terraform, the executor must independently verify:

1. request ID is valid and has not already completed successfully;
2. repository identity matches the reviewed repository;
3. source commit SHA matches the approved commit;
4. target environment matches the approved environment;
5. saved-plan artifact exists and is the expected artifact;
6. recomputed SHA-256 of the saved plan matches `planSha256`;
7. approval references the exact same plan SHA-256;
8. approval references the exact same commit SHA and environment;
9. approval is valid and not expired, revoked, or superseded;
10. provider lockfile hash matches the reviewed execution context;
11. Terraform version matches the permitted execution version;
12. all mandatory upstream gates remain PASS;
13. no newer plan has superseded the approved plan;
14. runner identity is authorized for the target environment;
15. execution command resolves exactly to the allowlisted saved-plan apply operation.

Failure of any precondition results in `BLOCKED`. No failed precondition may be converted to a warning.

### Terraform Command Authority

The Phase 2A execution capability is allowlist-based.

Permitted mutation command:

```text
terraform apply <exact-saved-plan-path>
```

The saved plan path must resolve to the artifact whose hash was independently verified immediately before execution. The executor must not expose a general-purpose Terraform or shell interface.

The following remain outside autonomous authority:

```text
terraform apply <configuration>
terraform apply -auto-approve <configuration>
terraform destroy
terraform import
terraform state rm
terraform state mv
terraform force-unlock
arbitrary terraform subcommands supplied by model output
arbitrary shell commands supplied by model output
```

Applying a saved plan does not require interactive approval at the CLI level, so `-auto-approve` is not itself the danger here — the danger is `apply` running against configuration rather than the reviewed saved plan. Adding any future command to the allowlist requires a separate authority review.

### Execution States

Phase 2A execution must use explicit states rather than boolean success/failure:

```text
REQUESTED
PRECONDITION_CHECK
BLOCKED
READY
APPLYING
APPLY_FAILED
PARTIALLY_APPLIED
APPLY_SUCCEEDED
EVIDENCE_RECORDED
COMPLETED
```

`APPLY_FAILED` does not imply that no infrastructure changed. If Terraform exits unsuccessfully after mutation may have begun, the system must conservatively treat the outcome as potentially partial until state and execution evidence establish otherwise. Phase 2A must never automatically retry an apply whose mutation status is ambiguous.

### Required Threat Cases

The Phase 2A design must explicitly demonstrate deterministic handling of:

- commit modified after approval;
- saved plan tampered with;
- approval replayed against another plan;
- approval replayed against another environment;
- approval replayed after expiry or revocation;
- superseded plan submitted for execution;
- provider lockfile changed after review;
- Terraform version changed between plan and apply;
- malicious pull request content;
- prompt injection attempting to invoke execution;
- fork-originated execution request;
- unauthorized runner identity;
- runner unavailable during execution;
- state-lock contention;
- Terraform apply returns non-zero;
- runner terminates during apply;
- partial infrastructure mutation;
- credentials accidentally appearing in output;
- duplicate/replayed execution request;
- attempt to invoke a forbidden Terraform or shell command.

For each threat, the design document must identify: **trust boundary → enforcement point → expected state → evidence emitted**.

### Expected Artifacts

Before implementation:

- `docs/phase-2a-execution-contract.md`
- `docs/phase-2a-threat-model.md`
- reviewed execution-request schema
- reviewed execution-result schema
- reviewed approval-record contract shared with Phase 2C
- explicit Terraform execution command allowlist
- threat-to-enforcement mapping

During implementation:

- deterministic execution-precondition evaluator
- execution state machine
- saved-plan artifact verifier
- execution evidence recorder
- non-production execution adapter
- unit/integration tests for all acceptance conditions

### Acceptance Criteria

#### Design acceptance — required before code

- Threat model reviewed and approved.
- Execution contract reviewed and approved.
- Approval-record contract reviewed and approved.
- Every prohibited action maps to a deterministic enforcement point.
- Every required threat case maps to an expected state and evidence record.
- Phase 2A remains limited to one designated non-production environment.

#### Runtime acceptance

- The exact approved saved plan executes successfully in the designated non-production environment.
- Changed commit SHA blocks execution.
- Changed or tampered plan artifact blocks execution.
- Plan-hash mismatch blocks execution.
- Expired approval blocks execution.
- Revoked or superseded approval blocks execution.
- Wrong environment blocks execution.
- Approval replay against another environment blocks execution.
- Provider-lock hash mismatch blocks execution.
- Terraform-version mismatch blocks execution.
- Unauthorized runner identity blocks execution.
- Fork-originated execution attempt blocks execution.
- Direct configuration-based apply is impossible through the executor.
- Forbidden Terraform/state commands are impossible through the executor.
- Arbitrary LLM-generated shell commands are impossible through the executor.
- Duplicate execution requests cannot silently cause repeated mutation.
- Apply failure is recorded explicitly.
- Ambiguous/partial apply is never automatically retried.
- Execution evidence is persisted and tied to request ID, commit SHA, plan hash, environment, runner identity, approval ID, and timestamps.
- No LLM-produced field can satisfy or override an execution precondition.
- Existing Phase 1 deterministic validation, security, risk, and PR review behavior remains unchanged.

---

## 4. Phase 2B — Remote Terraform Runner

### Objective
Select and integrate a controlled execution backend so that `terraform apply` never runs against arbitrary local/agent compute with long-lived credentials.

### Scope
- Choose the execution backend: HCP Terraform / Terraform Enterprise, a GitHub-hosted or self-hosted Actions runner with strict permissions, or another controlled runner — this is itself a decision to be made and documented, not assumed.
- Remote state storage and locking (moving off any local/implicit state).
- Workspace/environment isolation (dev/non-prod/prod do not share a workspace or state).
- Short-lived cloud credentials via OIDC federation — no static cloud keys in the repository or CI configuration.
- Apply is always performed from the reviewed saved plan artifact produced earlier in the chain, transported to the runner unmodified.

### Explicit Non-Goals
- No policy engine work (2H), no cost governance (2I) — this sub-phase is purely about *where and how* apply executes, not what gates it.
- No secrets manager integration beyond what's needed for OIDC credential exchange itself (broader secrets/identity work is 2F).

### Security / Trust Boundary
The runner is the component with actual cloud write access. It must be the most tightly scoped component in the system: least-privilege IAM per environment, no persistent credentials, and no path by which the LLM/agent process itself holds or can request elevated cloud credentials directly.

### Dependencies
- Phase 2A's execution contract (the runner is what 2A's "submit the exact approved saved plan to an authorized runner" step submits to).
- Cloud provider OIDC trust configuration (infrastructure/org-level setup, likely outside this repo alone).

### Expected Artifacts
- A written comparison/decision record for the backend choice.
- Runner configuration (workflow file or HCP Terraform workspace config) — kept out of scope until the decision above is made and reviewed.
- Updated `.agent/config.yaml`-style configuration describing per-environment workspace/credential mapping.

### Acceptance Criteria
- No static cloud credentials anywhere in the repository or CI configuration at any point, verifiable by inspection.
- Remote state with locking is demonstrably in place before any apply capability is enabled.
- Workspace isolation between at least two environments (e.g., dev and a non-prod stand-in) is demonstrated before prod is considered.

---

## 5. Phase 2C — Approval Workflow

### Objective
Produce a real, binding, plan-hash-bound human approval record that Phase 2A can verify before permitting apply.

### Scope
- GitHub Environment protection rules or an HCP Terraform approval gate — a real platform mechanism, not an application-level approximation.
- Named approvers / RBAC — approval must be attributable to a specific authorized human, not "someone with repo write access."
- The approval object binds:
  ```text
  requestId
  environment
  commit SHA
  plan SHA-256
  approver
  timestamp
  ```
- Any new commit or any new/regenerated plan invalidates the approval — this must be automatic and unconditional, not something a later step can override.

### Explicit Non-Goals
- No execution (2A) or runner (2B) work — 2C produces the approval record; it does not consume it.
- No new identity/hash mechanism of any kind — see the Plan-Hash Lineage invariant above. 2C extends `PullRequestReview`'s existing stale-plan-hash detection into a binding record; it does not invent a parallel one.

### Security / Trust Boundary
This is the human-in-the-loop control that everything downstream depends on. The approval record must be tamper-evident and must be impossible to satisfy by anything other than an actual authorized human action on the actual current plan hash. An LLM-driven or automated process must never be able to create, forge, or silently renew an approval record.

### Dependencies
- Phase 1E's plan-hash and stale-review-detection mechanism (extended, not replaced).
- A platform-level approval gate (GitHub Environments or HCP Terraform) — this is a real external dependency, not something built from scratch in application code.

### Expected Artifacts
- `schemas/approval.schema.json` already exists in the repository (Phase 1) — this sub-phase extends it to the full binding shape above rather than replacing it.
- Approval-record storage location and format (likely under `.agent/sessions/<request-id>/approval.json`, consistent with existing session-evidence conventions).

### Acceptance Criteria
- An approval record cannot be produced without a named, authenticated approver acting through the platform gate.
- Changing the commit SHA or the plan hash after approval demonstrably invalidates the existing approval record (automatically, not via a manual re-check step).
- The approval schema and the Phase 1E `PullRequestReview` plan-hash field are shown to use the same hash value/format — no translation layer that could silently diverge.

---

## 6. Phase 2D — Post-Deployment Verification

### Objective
Confirm that an apply actually produced the intended, desired-state outcome — not just that `terraform apply` returned exit code 0.

### Scope
- Verify resources actually reached the desired state described by the applied plan.
- Health checks and smoke tests appropriate to the deployed resources.
- Terraform state/plan reconciliation (a post-apply `terraform plan` should show no unexpected diff).
- Detect and surface partial applies explicitly — never let a partial apply be reported as a clean success.
- Record the deployment result into session evidence, linked to the same request/plan-hash lineage.

### Explicit Non-Goals
- No drift *detection over time* (that is 2E — 2D is the immediate post-apply check, 2E is the ongoing scheduled check).
- No automatic remediation of anything found here — surface and record, do not auto-fix.

### Security / Trust Boundary
Verification is read-only against the deployed infrastructure. It must not have any write/apply capability itself — a verification step that can also mutate infrastructure is a design smell.

### Dependencies
- Phase 2A/2B's execution result (what to verify against).
- Cloud read-only tooling already described in `Master-Prompt.txt` §21.

### Expected Artifacts
- A verification report format added to session evidence (alongside `result.json`, `plan.json`, etc.).
- Documented smoke-test/health-check hooks per resource class, extensible rather than hardcoded to one cloud.

### Acceptance Criteria
- A deliberately-induced partial-apply scenario is caught and reported as such, not as success.
- Post-apply `terraform plan` reconciliation is run and its result is recorded for every apply.

---

## 7. Phase 2E — Drift Detection

### Objective
Detect infrastructure that has diverged from the Terraform-managed desired state outside of this system's own applies.

### Scope
- Scheduled `terraform plan -detailed-exitcode` runs.
- Interpret exit codes (`0` = no differences, `1` = error, `2` = drift detected) and act only on `2`.
- On detected drift: open an issue/PR or alert — never automatically apply a "fix" to production drift.
- Distinguish *expected* drift (e.g., autoscaling-managed attributes) from *unauthorized* drift requiring attention — this distinction must be configurable, not hardcoded per resource.

### Explicit Non-Goals
- No automatic reconciliation/apply of any kind in response to drift. Ever, for production. This is a detection-and-alert sub-phase only.

### Security / Trust Boundary
Read-only (`terraform plan`) against real infrastructure on a schedule. No apply capability is exercised by this sub-phase under any circumstance.

### Dependencies
- Phase 2B's remote state/runner (drift checks run against the same state the controlled runner uses).

### Expected Artifacts
- A scheduled workflow (e.g., `.github/workflows/terraform-drift.yml`) distinct from the PR and apply workflows.
- A drift report format, and the issue/PR/alert template it produces.

### Acceptance Criteria
- A deliberately introduced out-of-band change is detected and reported without any code path that could apply a correction automatically.
- Expected-drift exclusions are demonstrably configuration, not code changes.

---

## 8. Phase 2F — Secrets & Identity

### Objective
Ensure no long-lived or plaintext credential material is ever visible to the LLM, stored in the repository, or held longer than necessary.

### Scope
- Vault / cloud-native secret manager integration (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, or HCP Terraform sensitive variables, per `Master-Prompt.txt` §34).
- OIDC federation for cloud credential exchange (shared with Phase 2B's runner).
- Least-privilege roles scoped per environment.
- Automated secret-redaction tests (verifying logs, PR comments, and session evidence never contain credential material).
- Credential lifetime controls — short-lived by default, no standing long-lived cloud keys.

### Explicit Non-Goals
- No new secret manager product evaluation beyond what's needed to satisfy the above — this is not a general secrets-management platform project.

### Security / Trust Boundary
The core invariant: **the LLM component must never see a credential value**, in a prompt, a tool result, a log, or a generated file. This must be tested, not just asserted.

### Dependencies
- Phase 2B (OIDC federation is shared infrastructure).

### Expected Artifacts
- Redaction test suite covering logs, session evidence JSON, and rendered PR/approval comments.
- Documented per-environment role/permission mapping.

### Acceptance Criteria
- A test that deliberately attempts to leak a credential value into a log or LLM-visible surface fails closed (is caught) rather than failing open.
- No static credential exists in the repository, CI config, or `.agent/` session artifacts — verifiable by a repository-wide scan.

---

## 9. Phase 2G — Module Governance

### Objective
Ensure Terraform modules used or proposed by the system come from a known, approved, version-pinned source.

### Scope
- Approved module catalog (which sources/registries are trusted).
- Version pinning enforcement.
- Private registry support if the organization requires it.
- Module contract/schema validation (inputs/outputs match what the module actually declares — consistent with the existing anti-hallucination rule for provider resources).
- Block unapproved module sources outright.
- Provider major-version upgrades are treated as their own reviewed change, never silently absorbed into an unrelated request (already a principle in `Master-Prompt.txt` §32; this sub-phase makes it enforced rather than advisory).

### Explicit Non-Goals
- No general package-manager-style dependency resolution beyond Terraform's own module/provider model.

### Security / Trust Boundary
An unapproved or unpinned module is a supply-chain risk. This sub-phase's gate must run before `AUTHOR`/`PLAN` stages can proceed with a module reference the catalog doesn't recognize.

### Dependencies
- None new beyond the existing provider-schema verification tooling (Phase 1).

### Expected Artifacts
- A module allowlist/catalog file under `policies/` (consistent with the existing `policies/terraform/` convention).
- A validation script analogous to `scripts/validate.sh` scoped to module sources.

### Acceptance Criteria
- A request referencing an unapproved module source is blocked before authoring proceeds, with a clear reason.
- A version-unpinned module reference is flagged, not silently accepted.

---

## 10. Phase 2H — Policy Maturity

### Objective
Expand policy enforcement from a single Checkov security gate (Phase 1) to a fuller OPA/Sentinel policy library covering organizational rules beyond generic security scanning.

### Scope
Policy areas to cover, at minimum:
- public networking
- IAM escalation
- encryption
- tagging
- approved regions
- instance classes
- database deletion protection
- backup rules
- cost ceilings (coordinated with Phase 2I, not duplicated)

Policy exceptions must themselves require their own approval and be recorded in the audit trail — an exception is not a way around governance, it's a governed action in itself.

### Explicit Non-Goals
- No replacement of Checkov (Phase 1's security gate stays); this adds an organizational-policy layer alongside it, per `Master-Prompt.txt` §17.

### Security / Trust Boundary
Policy evaluation remains deterministic (OPA/Sentinel/Conftest against plan JSON) — never an LLM judgment call on whether a policy is satisfied.

### Dependencies
- Phase 1's plan JSON output (policy evaluates the same `plan.json` already produced).

### Expected Artifacts
- Policy files under `policies/` per area (`policies/terraform/`, plus new subdirectories as needed, consistent with the existing `policies/security/`, `policies/cost/`, `policies/tagging/` layout already sketched in `Master-Prompt.txt` §30).
- An exception-request/approval record format, following the same plan-hash/approval-record conventions as Phase 2C.

### Acceptance Criteria
- Each listed policy area has at least one automated test proving both a passing and a failing case.
- A policy exception cannot be applied without its own recorded approval, distinct from the underlying change's approval.

---

## 11. Phase 2I — Cost Governance

### Objective
Make Infracost a first-class, enforced gate rather than an optional report.

### Scope
- Absolute and percentage cost-delta thresholds (building on the existing `CostDelta`/`InfracostCostService` model from Phase 1D).
- Monthly projected cost delta, per the existing thresholds already defined in `Master-Prompt.txt` §18 (>10% warning, >20% approval required, >50% financial review) — this sub-phase makes those thresholds enforced in the real pipeline, not just documented.
- Environment-specific budgets (a dev budget is not a prod budget).
- Expensive-resource warnings independent of percentage delta (a small percentage change on a very large base cost still matters).
- Optional FinOps approval path for large increases, following the same approval-record shape as Phase 2C.

### Explicit Non-Goals
- No general cloud cost optimization/recommendation engine — this is a governance gate, not a cost-management product.

### Security / Trust Boundary
Cost evaluation is deterministic (Infracost output parsed by `InfracostCostService`, already unit-tested in Phase 1D). No LLM estimation of cost is authoritative.

### Dependencies
- Phase 1D's `CostDelta`/`InfracostCostService` (already implemented and tested — this sub-phase wires it into the enforced pipeline and CI, and adds environment-aware budgets, rather than rebuilding cost parsing).

### Expected Artifacts
- Per-environment budget configuration (extending `.agent/config.yaml`'s existing `cost:` section from `Master-Prompt.txt` §42).
- FinOps approval record format.

### Acceptance Criteria
- A plan exceeding the approval threshold is demonstrably blocked pending approval, not just flagged in a comment.
- Per-environment budgets are shown to produce different outcomes for the same absolute cost change in dev vs. prod.

---

## 12. Preliminary Phase 2A Authority Boundaries

Documented here as the explicit boundary for design review — **nothing in this section is implemented**.

### The system may eventually:
- prepare an execution request
- verify plan hash
- verify commit SHA
- verify approval
- verify environment
- verify policy/security results
- submit the exact approved saved plan to an authorized runner
- record execution evidence

### It must not autonomously:
- run `terraform destroy`
- perform `terraform state rm`
- perform `terraform state mv`
- run `terraform force-unlock`
- perform `terraform import`
- bypass human approval
- regenerate an approved plan and treat it as equivalent
- widen its own cloud permissions
- bypass security/policy gates
- execute arbitrary shell commands supplied by an LLM

**Production execution must remain approval-gated.** This list is a superset restatement of `Master-Prompt.txt` §3 ("The agent MAY NOT autonomously") and §28 ("Forbidden Autonomous Commands"), made explicit for the execution-authority context specifically. Where this list and `Master-Prompt.txt` ever appear to differ, the more restrictive statement governs.

---

## 13. Enterprise v1 Completion Gates

```text
[x] deterministic Terraform validation
[x] provider-schema enforcement
[x] lint/security gates
[x] real plan parsing
[x] risk engine
[x] plan-hash primitive
[x] deterministic PR review
[x] remote PR acceptance

[ ] controlled execution
[ ] remote state and locking
[ ] short-lived cloud authentication
[ ] approval enforcement
[ ] post-apply verification
[ ] drift detection
[ ] secrets integration
[ ] module governance
[ ] production policy pack
[ ] cost governance
[ ] observability/audit
[ ] threat-model/security hardening
[ ] real non-production end-to-end deployment
```

The checked items above correspond to Phase 1A-1E, checkpointed at `phase-1e-checkpoint`. Each unchecked item corresponds to one or more sub-phases above:

| Gate | Sub-phase(s) |
|---|---|
| controlled execution | 2A |
| remote state and locking | 2B |
| short-lived cloud authentication | 2B, 2F |
| approval enforcement | 2C |
| post-apply verification | 2D |
| drift detection | 2E |
| secrets integration | 2F |
| module governance | 2G |
| production policy pack | 2H |
| cost governance | 2I |
| observability/audit | cross-cutting, tracked per sub-phase's acceptance criteria rather than a standalone phase |
| threat-model/security hardening | primarily 2A (execution) and 2F (secrets), but every sub-phase's "Security / Trust Boundary" section contributes |
| real non-production end-to-end deployment | the integration milestone that proves 2A-2D work together, not a sub-phase in itself |

The system is "functionally complete v1" once a real non-production deployment has traversed the full execution chain in §2 end-to-end at least once, with every gate above checked.

---

## 14. Process Note

This document was created as a documentation-only baseline commit, per explicit user authorization to begin Phase 2 on 2026-09-10, immediately following the design constraint that Phase 2A requires a reviewed threat model and execution contract *before* any implementation. The next step, before any 2A code, is that design review — see §3 and §12 above for what it must settle.
