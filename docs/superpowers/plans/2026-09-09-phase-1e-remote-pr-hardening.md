# Phase 1E: Remote GitHub PR Acceptance & Review UX Hardening — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This plan is executed **inline in the current session**, not subagent-driven, because the final tasks require live, credentialed `gh`/`git` interaction against the user's real GitHub repository with judgment calls that must stay in one continuous thread (branch naming, run polling, evidence capture, cleanup).

**Goal:** Make the Phase 1D Terraform PR-review pipeline (`.github/workflows/terraform-pr.yml` + `scripts/terraform-pr-review.sh`) safe and correct against real GitHub pull requests — single marker-backed comment lifecycle, stale-hash invalidation, accurate ELIGIBLE/APPROVAL_REQUIRED/BLOCKED rendering, least-privilege token scope, fork-PR safety — and prove it end-to-end against real PRs on `haftomalemayehu/IAC-Agent`.

**Architecture:** The actual runtime PR-review pipeline is GitHub Actions YAML + a bash/python script driving `gh api` — the Java classes (`PullRequestReview`, `ReviewDecisionEngine`, `GitHubPrCommentRenderer`, `GitHubReviewCommentManager`, `InfracostCostService`, `CostDelta`) are a parallel, unit-tested reference model that documents the intended decision/render logic but is **not** invoked by CI today. This plan (a) fixes the Java model so its own test suite passes and its rendering matches the real comment format, (b) extracts the script's inline markdown generation into a standalone, locally-testable Python module, (c) hardens the workflow/script for least privilege, fork safety, resilient (non-abort) stage evaluation, and honest error surfacing, and (d) validates all of it against real PRs. No new services, agents, or execution authority are added.

**Tech Stack:** Java 21 / Spring Boot (Gradle, JUnit 5), GitHub Actions YAML, bash, Python 3 (already used inline in the workflow), `gh` CLI.

**Spec:** The user's Phase 1E task description (this conversation) is the spec; there is no separate spec doc. Key source docs to respect: `agent/CONTRACT.md`, `agent/POLICY.md`, `agent/WORKFLOW.md`, root `CLAUDE.md`.

## Global Constraints

- Do not add HCP Terraform, MCP execution authority, cloud writes, extra agents, or production apply.
- Do not modify unrelated infrastructure; use the smallest safe change (per `CLAUDE.md`).
- Never push to a protected branch; production apply and destructive/state-changing ops require explicit approval (`agent/CONTRACT.md`).
- PASS/FAIL/BLOCKED/NOT RUN semantics from `agent/POLICY.md` must be respected everywhere a stage status is reported.
- Never claim validation succeeded unless the command actually ran successfully — evidence must be real command output, not asserted.
- Fork PRs and untrusted contributions must not gain write or deployment authority — GitHub's own token scoping for `pull_request` from forks (read-only, no secrets) is the primary control; the workflow must not weaken it, and should add an explicit, defense-in-depth guard.
- Stop after Phase 1E acceptance evidence is produced — no further phases, no merge to `main` unless the user asks.

---

### Task 1: Fix and extend the Java PR-review markdown renderer

**Files:**
- Modify: `src/main/java/com/iacagent/iacagent/PullRequestReview.java`
- Modify: `src/test/java/com/iacagent/iacagent/Phase1dTests.java` (only if an assertion needs a trivial adjustment to match the agreed real format — prefer changing the renderer, not the test)
- Create: `src/test/java/com/iacagent/iacagent/Phase1eTests.java`

**Interfaces:**
- Consumes: existing `PlanSummary`, `ResourceChange`, `ValidationState`, `RiskLevel`, `CostDelta`, `ReviewDecision` — no signature changes.
- Produces: `PullRequestReview.markdown()` (unchanged signature, used by existing tests) plus a new overload `PullRequestReview.markdown(String ciRunUrl, String priorPlanHash)` that later tasks and future callers can use to render an evidence run link and a stale-review notice. `evidenceReference` field/semantics unchanged.

Today `./gradlew test` fails on `Phase1dTests.prCommentRendererIncludesRequiredSections` because `markdown()` doesn't emit `"Terraform IaC Review"`, `"Decision: ..."`, `"### Plan"`, `"### Security"`, or `"### Cost"`. Fix the renderer itself (it's also the least-clear part of the current output — no cost section, no run link, no way to say "this supersedes an earlier stale review").

- [ ] **Step 1: Confirm the current failure**

Run: `./gradlew test --tests "com.iacagent.iacagent.Phase1dTests" --console=plain`
Expected: `prCommentRendererIncludesRequiredSections` FAILS; all other Phase1dTests PASS.

- [ ] **Step 2: Write the new failing tests for the extended renderer (staleness + run link)**

Add to `src/test/java/com/iacagent/iacagent/Phase1eTests.java`:

```java
package com.iacagent.iacagent;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class Phase1eTests {

    private PullRequestReview eligibleReview(String planHash) {
        PlanSummary plan = new PlanSummary(2, 1, 0, 0, 0, List.of());
        return PullRequestReview.fromEvidence(
                planHash,
                plan,
                RiskLevel.LOW,
                ValidationState.PASS,
                ValidationState.PASS,
                ValidationState.PASS,
                CostDelta.notRun("Infracost not executed"),
                List.of(),
                List.of()
        );
    }

    @Test
    void markdownWithRunLinkIncludesCiRunReference() {
        PullRequestReview review = eligibleReview("sha256:aaa");
        String markdown = review.markdown("https://github.com/acme/repo/actions/runs/123", null);
        assertTrue(markdown.contains("https://github.com/acme/repo/actions/runs/123"));
        assertTrue(markdown.contains("### Evidence"));
    }

    @Test
    void markdownNotesWhenSupersedingAStalePriorReview() {
        PullRequestReview review = eligibleReview("sha256:bbb");
        String markdown = review.markdown("https://github.com/acme/repo/actions/runs/124", "sha256:aaa");
        assertTrue(markdown.contains("sha256:aaa"), "should reference the superseded plan hash");
        assertTrue(markdown.toLowerCase().contains("supersede") || markdown.toLowerCase().contains("stale"));
    }

    @Test
    void markdownDoesNotMentionStalenessWhenHashUnchanged() {
        PullRequestReview review = eligibleReview("sha256:ccc");
        String markdown = review.markdown("https://github.com/acme/repo/actions/runs/125", "sha256:ccc");
        assertFalse(markdown.toLowerCase().contains("supersede"));
    }

    @Test
    void blockedDecisionRendersBlockedLiterally() {
        PlanSummary plan = new PlanSummary(1, 0, 0, 0, 0, List.of());
        PullRequestReview review = PullRequestReview.fromEvidence(
                "sha256:ddd", plan, RiskLevel.LOW,
                ValidationState.PASS, ValidationState.FAIL, ValidationState.PASS,
                CostDelta.notRun("n/a"), List.of(), List.of()
        );
        assertEquals(ReviewDecision.BLOCKED, review.decision());
        assertTrue(review.markdown().contains("Decision: BLOCKED"));
    }
}
```

- [ ] **Step 3: Run the new tests to verify they fail**

Run: `./gradlew test --tests "com.iacagent.iacagent.Phase1eTests" --console=plain`
Expected: FAIL — `markdown(String, String)` does not exist (compile error) or assertions fail once it compiles minimally.

- [ ] **Step 4: Rewrite `PullRequestReview.markdown()`**

Replace the `markdown()` method and add the new overload in `src/main/java/com/iacagent/iacagent/PullRequestReview.java`:

```java
    public String markdown() {
        return markdown(null, null);
    }

    public String markdown(String ciRunUrl, String priorPlanHash) {
        StringBuilder sb = new StringBuilder();
        sb.append("<!-- terraform-review -->\n");
        sb.append("## Terraform IaC Review\n\n");
        if (priorPlanHash != null && planHash != null && !priorPlanHash.equals(planHash)) {
            sb.append("> **Note:** This review supersedes a stale prior review (plan hash `")
                    .append(priorPlanHash)
                    .append("`). The plan changed since that review; treat only this comment as current.\n\n");
        }
        sb.append("Decision: ").append(decision.name()).append("\n");
        sb.append("Risk: ").append(risk.name()).append("\n\n");

        sb.append("### Plan\n");
        if (plan == null) {
            sb.append("- No plan summary available\n");
        } else {
            sb.append("- create: ").append(plan.create()).append("\n");
            sb.append("- update: ").append(plan.update()).append("\n");
            sb.append("- replace: ").append(plan.replace()).append("\n");
            sb.append("- destroy: ").append(plan.destroy()).append("\n");
        }

        sb.append("\n### Security\n");
        sb.append("- Schema: ").append(schema == null ? ValidationState.NOT_RUN : schema).append("\n");
        sb.append("- Validate: ").append(validate == null ? ValidationState.NOT_RUN : validate).append("\n");
        sb.append("- Security: ").append(security == null ? ValidationState.NOT_RUN : security).append("\n");

        sb.append("\n### Cost\n");
        if (cost == null || cost.status() == ValidationState.NOT_RUN) {
            sb.append("- NOT_RUN").append(cost != null && cost.message() != null ? " (" + cost.message() + ")" : "").append("\n");
        } else if (cost.status() == ValidationState.BLOCKED) {
            sb.append("- BLOCKED (").append(cost.message()).append(")\n");
        } else {
            sb.append("- ").append(cost.deltaPercent() >= 0 ? "+" : "").append(String.format("%.1f", cost.deltaPercent()))
                    .append("% ($").append(String.format("%.2f", cost.currentMonthly()))
                    .append(" -> $").append(String.format("%.2f", cost.proposedMonthly())).append(")\n");
        }

        sb.append("\n### Critical changes\n");
        if (criticalChanges.isEmpty()) {
            sb.append("- None\n");
        } else {
            for (String item : criticalChanges) {
                sb.append("- ").append(item).append("\n");
            }
        }

        sb.append("\n### Approval reasons\n");
        if (reasons.isEmpty()) {
            sb.append("- None\n");
        } else {
            for (String reason : reasons) {
                sb.append("- ").append(reason).append("\n");
            }
        }

        sb.append("\n### Evidence\n");
        sb.append("- Plan hash: ").append(planHash == null ? "sha256:unknown" : planHash).append("\n");
        if (ciRunUrl != null && !ciRunUrl.isBlank()) {
            sb.append("- CI run: ").append(ciRunUrl).append("\n");
        }
        sb.append("- Artifact: ").append(evidenceReference).append("\n");
        return sb.toString();
    }
```

Delete the now-unused private `planSummaryHeader()` helper (its content is folded into the `### Plan` section above); keep `inferCriticalChanges()` as-is.

- [ ] **Step 5: Run both test classes to verify everything passes**

Run: `./gradlew test --tests "com.iacagent.iacagent.Phase1dTests" --tests "com.iacagent.iacagent.Phase1eTests" --console=plain`
Expected: PASS, all tests green.

- [ ] **Step 6: Run the full suite**

Run: `./gradlew test --console=plain`
Expected: `BUILD SUCCESSFUL`, all tests (including `IacAgentApplicationTests`, `IacAgentServiceTests`, `Phase1bTests`) pass.

- [ ] **Step 7: Commit**

```bash
git add src/main/java/com/iacagent/iacagent/PullRequestReview.java src/test/java/com/iacagent/iacagent/Phase1eTests.java
git commit -m "Fix and extend PR review markdown renderer for reviewer clarity"
```

---

### Task 2: Extract the CI comment-body renderer into a standalone, locally-testable script

**Files:**
- Create: `scripts/render_pr_review.py`
- Modify: `scripts/terraform-pr-review.sh` (call the new script instead of an inline heredoc)

**Interfaces:**
- Consumes: `.agent/sessions/ci-evidence/result.json`, `plan-summary.json`, `.agent/artifacts/tfplan.sha256` (all already produced by `terraform-pr.yml`); optional `--ci-run-url`, `--prior-plan-hash`, `--prior-body-file` CLI args.
- Produces: rendered markdown on stdout, and the raw decision (`ELIGIBLE`/`APPROVAL_REQUIRED`/`BLOCKED`) on stderr's last line prefixed `DECISION=` for the caller to branch on if ever needed (kept simple — the shell script doesn't currently need to branch on decision text, only pass through the body).

This is a pure extraction (no behavior change) so the render logic can be unit-exercised locally against synthetic evidence directories before ever touching a real PR — see Task 4.

- [ ] **Step 1: Write `scripts/render_pr_review.py`**

```python
#!/usr/bin/env python3
"""Render the Terraform PR review comment body from CI evidence.

Pure function of the evidence directory + optional prior-review context.
No network calls — safe to run locally against synthetic evidence for
manual/automated verification before wiring into a real PR.
"""
import argparse
import json
import pathlib

MARKER = "<!-- terraform-review -->"


def load_json(path: pathlib.Path, default):
    return json.loads(path.read_text()) if path.exists() else default


def stage_status(result: dict, stage: str) -> str:
    return result.get("stages", {}).get(stage, "NOT_RUN")


def render(evidence_dir: pathlib.Path, plan_hash: str, ci_run_url: str | None, prior_plan_hash: str | None) -> str:
    result = load_json(evidence_dir / "result.json", {})
    plan = load_json(evidence_dir / "plan-summary.json", {"create": 0, "update": 0, "replace": 0, "destroy": 0})

    schema = stage_status(result, "providerSchema")
    validate = stage_status(result, "validate")
    security = stage_status(result, "security")
    risk = result.get("risk", "LOW")

    critical = []
    if plan.get("replace", 0) > 0:
        critical.append("aws resources will be replaced")
    if plan.get("destroy", 0) > 0:
        critical.append("destroy actions are present")

    reasons = []
    if plan.get("replace", 0) > 0:
        reasons.append("RESOURCE_REPLACEMENT")
    if plan.get("destroy", 0) > 0:
        reasons.append("RESOURCE_DESTRUCTION")
    if risk in {"HIGH", "CRITICAL"}:
        reasons.append("HIGH_RISK")
    for stage_name, status in (("security", security), ("validate", validate), ("providerSchema", schema)):
        if status in {"FAIL", "BLOCKED"}:
            reasons.append(f"{stage_name.upper()}_{status}")

    if security in {"FAIL", "BLOCKED"} or validate in {"FAIL", "BLOCKED"} or schema in {"FAIL", "BLOCKED"}:
        decision = "BLOCKED"
    elif plan.get("replace", 0) > 0 or plan.get("destroy", 0) > 0 or risk in {"HIGH", "CRITICAL"}:
        decision = "APPROVAL_REQUIRED"
    else:
        decision = "ELIGIBLE"

    lines = [MARKER, "## Terraform IaC Review", ""]
    if prior_plan_hash and prior_plan_hash != plan_hash:
        lines += [
            f"> **Note:** This review supersedes a stale prior review (plan hash `{prior_plan_hash}`). "
            "The plan changed since that review; treat only this comment as current.",
            "",
        ]
    lines += [
        f"Decision: {decision}",
        f"Risk: {risk}",
        "",
        "### Plan",
        f"- create: {plan.get('create', 0)}",
        f"- update: {plan.get('update', 0)}",
        f"- replace: {plan.get('replace', 0)}",
        f"- destroy: {plan.get('destroy', 0)}",
        "",
        "### Security",
        f"- Schema: {schema}",
        f"- Validate: {validate}",
        f"- Security: {security}",
        "",
        "### Critical changes",
    ]
    lines += [f"- {item}" for item in critical] if critical else ["- None"]
    lines += ["", "### Approval reasons"]
    lines += [f"- {item}" for item in reasons] if reasons else ["- None"]
    lines += ["", "### Evidence", f"- Plan hash: {plan_hash}"]
    if ci_run_url:
        lines.append(f"- CI run: {ci_run_url}")
    lines.append("- Artifact: terraform-evidence")
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", required=True, type=pathlib.Path)
    parser.add_argument("--plan-hash", required=True)
    parser.add_argument("--ci-run-url", default=None)
    parser.add_argument("--prior-plan-hash", default=None)
    args = parser.parse_args()
    print(render(args.evidence_dir, args.plan_hash, args.ci_run_url, args.prior_plan_hash))


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Make it executable**

Run: `chmod +x scripts/render_pr_review.py`

- [ ] **Step 3: Smoke-test it against the existing committed CI evidence fixture**

Run:
```bash
python3 scripts/render_pr_review.py \
  --evidence-dir .agent/sessions/ci-evidence \
  --plan-hash "sha256:smoketest" \
  --ci-run-url "https://github.com/haftomalemayehu/IAC-Agent/actions/runs/0"
```
Expected: prints a markdown body starting with `<!-- terraform-review -->` / `## Terraform IaC Review`, with a `Decision:` line and all five `###` sections. No traceback.

- [ ] **Step 4: Rewire `scripts/terraform-pr-review.sh` to call it**

Replace the inline `python3 - <<'PY' ... PY` block and the `BODY=` construction in `scripts/terraform-pr-review.sh` with:

```bash
CI_RUN_URL=""
if [[ -n "${GITHUB_SERVER_URL:-}" && -n "${GITHUB_REPOSITORY:-}" && -n "${GITHUB_RUN_ID:-}" ]]; then
  CI_RUN_URL="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
fi

PR_NUMBER="$(gh pr view --json number -q .number 2>/dev/null || true)"
if [[ -z "$PR_NUMBER" ]]; then
  echo "No PR associated with this checkout"
  exit 0
fi

if ! COMMENTS_JSON="$(gh api "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" --paginate 2>/tmp/comments_err.log)"; then
  echo "FAIL: could not list existing PR comments (permissions or API error):" >&2
  cat /tmp/comments_err.log >&2
  exit 1
fi

EXISTING_ID="$(echo "$COMMENTS_JSON" | jq -r ".[] | select(.body | contains(\"${MARKER}\")) | .id" | head -n 1)"
PRIOR_PLAN_HASH=""
if [[ -n "$EXISTING_ID" ]]; then
  PRIOR_BODY="$(echo "$COMMENTS_JSON" | jq -r ".[] | select(.id == ${EXISTING_ID}) | .body")"
  PRIOR_PLAN_HASH="$(echo "$PRIOR_BODY" | grep -o 'Plan hash: sha256:[a-f0-9]*' | head -n 1 | sed 's/Plan hash: //')"
fi

BODY="$(python3 scripts/render_pr_review.py \
  --evidence-dir "$ARTIFACT_DIR" \
  --plan-hash "$HASH_VALUE" \
  --ci-run-url "$CI_RUN_URL" \
  --prior-plan-hash "$PRIOR_PLAN_HASH")"

if [[ -n "$EXISTING_ID" ]]; then
  if ! gh api --method PATCH "repos/${GITHUB_REPOSITORY}/issues/comments/${EXISTING_ID}" -f body="$BODY" >/dev/null; then
    echo "FAIL: could not update existing review comment ${EXISTING_ID}" >&2
    exit 1
  fi
else
  if ! gh api --method POST "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" -f body="$BODY" >/dev/null; then
    echo "FAIL: could not create review comment" >&2
    exit 1
  fi
fi
```

Keep the earlier lines of the script (the `ROOT`, `GITHUB_REPOSITORY` guard, `gh` presence check, `PLAN_HASH`/`HASH_VALUE` computation, `ARTIFACT_DIR`/`PLAN_PATH`/`MARKER` variables) as they are — only the body-construction and comment-publish section changes. This removes the old `EXISTING_ID=... || true` pattern that silently collapsed real API failures into "create a new comment," which risked duplicate comments on transient errors.

- [ ] **Step 5: Verify the script still parses with `bash -n`**

Run: `bash -n scripts/terraform-pr-review.sh`
Expected: no output, exit 0.

- [ ] **Step 6: Commit**

```bash
git add scripts/render_pr_review.py scripts/terraform-pr-review.sh
git commit -m "Extract PR review renderer and harden comment publish error handling"
```

---

### Task 3: Harden the workflow — least-privilege permissions, fork-PR guard, resilient stage evaluation

**Files:**
- Modify: `.github/workflows/terraform-pr.yml`

**Interfaces:**
- Consumes: nothing new.
- Produces: `.agent/sessions/ci-evidence/result.json` with **accurate** (not hardcoded) `init`/`providerSchema`/`validate`/`test`/`plan` stage statuses, so a real Terraform validation failure actually surfaces as `BLOCKED` in the posted comment instead of aborting the job before any comment is posted.

Two independent problems today:
1. No explicit `permissions:` block — the job inherits whatever the repo/org default is. Least privilege requires being explicit: `contents: read`, `pull-requests: write`, nothing else.
2. Every `terraform ...` step is a hard failure that aborts the job, so a genuinely BLOCKED PR (e.g. invalid attribute) never reaches the "Publish IaC review comment" step — reviewers get a red X and no explanation instead of a BLOCKED comment. Also `result.json` hardcodes `"init": "PASS", "providerSchema": "PASS", "validate": "PASS", "test": "PASS", "plan": "PASS"` regardless of actual outcome — only `lint`/`security` are computed for real.

- [ ] **Step 1: Add an explicit least-privilege `permissions:` block and a fork guard**

At the top of the `terraform-evidence` job in `.github/workflows/terraform-pr.yml`, add:

```yaml
permissions:
  contents: read
  pull-requests: write
```

(placed at job level, directly under `terraform-evidence:` and above `runs-on:`). This is the only permission the job needs — the checkout is `contents: read`, and the review comment step needs `pull-requests: write`. No `issues: write`, no `id-token`, no `packages`, nothing else.

Change the "Publish IaC review comment" step's `if:` condition from just checking the event name to also excluding forks, since a forked contributor's `GITHUB_TOKEN` is already read-only by GitHub for the `pull_request` trigger — this is defense-in-depth documentation of that fact, not a new mechanism:

```yaml
      - name: Publish IaC review comment
        if: github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: bash scripts/terraform-pr-review.sh
```

- [ ] **Step 2: Make the Terraform stages tolerant so the pipeline always reaches evidence publishing**

Add `continue-on-error: true` and an `id:` to each stage step that can legitimately fail for content reasons (not infra reasons) — `Terraform validate`, `TFLint`, `Checkov`, `Terraform test`, `Terraform plan`, `Show Terraform plan json`. Example for validate (apply the same pattern to the other four):

```yaml
      - name: Terraform validate
        id: validate
        continue-on-error: true
        run: terraform -chdir=tests/fixtures/valid-vpc validate -json > .agent/sessions/ci-evidence/validate.json
```

Add `if: always()` to "Publish Terraform evidence summary", "Archive evidence bundle", and "Publish IaC review comment" so they run even when an earlier stage failed:

```yaml
      - name: Publish Terraform evidence summary
        if: always()
        run: |
          ...
      - name: Archive evidence bundle
        if: always()
        uses: actions/upload-artifact@v4
        ...
      - name: Publish IaC review comment
        if: always() && github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository
        ...
```

Leave "Terraform fmt check" and "Terraform init backend false" and "Provider schema" as hard failures — a repo that doesn't even init/format cleanly is a genuine infra-setup problem, not a PR-content decision the reviewer needs to see rendered; keep the smallest safe change and don't paper over those.

- [ ] **Step 3: Fix the Python evidence-summary step to compute real stage statuses instead of hardcoding PASS**

Replace the hardcoded `"init": "PASS", "providerSchema": "PASS", "validate": "PASS", "test": "PASS", "plan": "PASS"` line in the "Publish Terraform evidence summary" step's embedded Python with real reads:

```python
          validate_doc = json.loads(pathlib.Path('.agent/sessions/ci-evidence/validate.json').read_text()) if pathlib.Path('.agent/sessions/ci-evidence/validate.json').exists() else None
          validate_pass = bool(validate_doc) and validate_doc.get('valid', False) is True
          plan_artifact_present = pathlib.Path('.agent/artifacts/tfplan').exists()
          plan_json_present = plan_path.exists()
          schema_present = pathlib.Path('.agent/cache/provider-schema.json').exists()
          test_doc_present = pathlib.Path('.agent/sessions/ci-evidence/test.json').exists()
```

and change the `result.json` write to:

```python
          pathlib.Path('.agent/sessions/ci-evidence/result.json').write_text(json.dumps({
              "requestId": "ci-evidence",
              "validity": "PASS" if validate_pass else "FAIL",
              "risk": "LOW",
              "deploymentEligibility": "ELIGIBLE",
              "stages": {
                  "init": "PASS",
                  "providerSchema": "PASS" if schema_present else "BLOCKED",
                  "fmt": "PASS",
                  "validate": "PASS" if validate_pass else "FAIL",
                  "lint": "PASS" if lint_pass else "FAIL",
                  "security": "PASS" if security_pass else "FAIL",
                  "test": "PASS" if test_doc_present else "BLOCKED",
                  "plan": "PASS" if (plan_artifact_present and plan_json_present) else "BLOCKED"
              },
              "plan": summary
          }, indent=2))
```

(`init` stays `"PASS"` because if `git checkout`/`terraform init` itself failed, `continue-on-error` was deliberately *not* set on that step in Step 2, so we'd never reach this point at all — its presence here is only reached on success.)

- [ ] **Step 4: Validate YAML syntax**

Run: `python3 -c "import yaml, sys; yaml.safe_load(open('.github/workflows/terraform-pr.yml'))" 2>&1 || (pip install --quiet pyyaml && python3 -c "import yaml; yaml.safe_load(open('.github/workflows/terraform-pr.yml'))")`
Expected: no exception raised (confirms the YAML parses).

Also run, if available: `gh workflow view terraform-pr --repo haftomalemayehu/IAC-Agent 2>&1 || true` (informational only, not blocking — the real syntax proof is the successful run in Task 5).

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/terraform-pr.yml
git commit -m "Harden PR review workflow: least-privilege permissions, fork guard, resilient stage evaluation"
```

---

### Task 4: Local dry-run of all three decisions before touching real GitHub

**Files:**
- Create (scratch, not committed): three synthetic evidence directories under the session scratchpad, e.g. `/private/tmp/claude-501/.../scratchpad/phase1e-dryrun/{eligible,approval_required,blocked}/`

**Interfaces:**
- Consumes: `scripts/render_pr_review.py` from Task 2.
- Produces: three markdown bodies proving each decision renders distinctly and correctly, captured as terminal output evidence — this is the offline proof that reduces risk before spending real PR/CI cycles in Task 5.

- [ ] **Step 1: Build three synthetic `result.json` + `plan-summary.json` pairs**

In the scratchpad, create:
- `eligible/result.json`: `{"stages": {"providerSchema": "PASS", "validate": "PASS", "security": "PASS"}, "risk": "LOW"}`, `eligible/plan-summary.json`: `{"create": 2, "update": 1, "replace": 0, "destroy": 0}`
- `approval_required/result.json`: `{"stages": {"providerSchema": "PASS", "validate": "PASS", "security": "PASS"}, "risk": "HIGH"}`, `approval_required/plan-summary.json`: `{"create": 1, "update": 0, "replace": 1, "destroy": 0}`
- `blocked/result.json`: `{"stages": {"providerSchema": "PASS", "validate": "FAIL", "security": "PASS"}, "risk": "LOW"}`, `blocked/plan-summary.json`: `{"create": 0, "update": 0, "replace": 0, "destroy": 0}`

- [ ] **Step 2: Render each and check the decision line**

Run for each of the three directories:
```bash
python3 scripts/render_pr_review.py --evidence-dir <dir> --plan-hash "sha256:dryrun"
```
Expected: `eligible` → `Decision: ELIGIBLE`; `approval_required` → `Decision: APPROVAL_REQUIRED` and `### Critical changes` lists "aws resources will be replaced"; `blocked` → `Decision: BLOCKED`.

- [ ] **Step 3: Render the `eligible` case twice with a changed plan hash to prove staleness rendering**

```bash
python3 scripts/render_pr_review.py --evidence-dir <eligible-dir> --plan-hash "sha256:new" --prior-plan-hash "sha256:old"
```
Expected: output contains the "supersedes a stale prior review" note referencing `sha256:old`.

No commit for this task — it's verification only, using scratch files outside the repo.

---

### Task 5: Commit outstanding Phase 1D work

**Files:** the currently-untracked Phase 1D files already on disk (per `git status`): `src/main/java/com/iacagent/iacagent/{CostDelta,GitHubPrCommentRenderer,GitHubReviewCommentManager,InfracostCostService,PullRequestReview,ReviewDecision,ReviewDecisionEngine}.java`, `src/test/java/com/iacagent/iacagent/Phase1dTests.java`, plus the modified `.agent/artifacts/tfplan`, `.agent/sessions/ci-evidence/{plan,test}.json`.

These represent completed-but-uncommitted Phase 1D work sitting in the working tree. Phase 1E task 1 above already modified `PullRequestReview.java`, so committing this now means Task 1's diff and this diff land together in history unless separated — that's fine; do it as one clean commit for the pre-existing Phase 1D files, since Task 1 already made its own commit on top of `PullRequestReview.java` in Task 1 Step 7. Reorder: **run this task's commit before Task 1's commit** if executing strictly in order 1→5 would otherwise stage Task 1's edits into the wrong commit. Since Task 1 already ran first per this plan's ordering, `PullRequestReview.java` is already committed with the Phase 1E message — that is acceptable (the file's Phase-1D origin and Phase-1E fix are inseparable in one file's history here); just commit the remaining untouched Phase 1D files now.

- [ ] **Step 1: Review what's left uncommitted**

Run: `git status --short`
Expected: shows the remaining new/modified files not yet part of a Task 1/2/3 commit (the `.agent/artifacts/tfplan`, `.agent/sessions/ci-evidence/plan.json`, `.agent/sessions/ci-evidence/test.json`, and any Phase-1D `.java` files Task 1 didn't touch, e.g. `CostDelta.java`, `GitHubPrCommentRenderer.java`, `GitHubReviewCommentManager.java`, `InfracostCostService.java`, `ReviewDecision.java`, `ReviewDecisionEngine.java`).

- [ ] **Step 2: Stage and commit them**

```bash
git add src/main/java/com/iacagent/iacagent/CostDelta.java \
        src/main/java/com/iacagent/iacagent/GitHubPrCommentRenderer.java \
        src/main/java/com/iacagent/iacagent/GitHubReviewCommentManager.java \
        src/main/java/com/iacagent/iacagent/InfracostCostService.java \
        src/main/java/com/iacagent/iacagent/ReviewDecision.java \
        src/main/java/com/iacagent/iacagent/ReviewDecisionEngine.java \
        src/test/java/com/iacagent/iacagent/Phase1dTests.java \
        .agent/artifacts/tfplan \
        .agent/sessions/ci-evidence/plan.json \
        .agent/sessions/ci-evidence/test.json
git commit -m "Complete Phase 1D PR review decision model"
```

- [ ] **Step 3: Full local verification before touching GitHub**

Run: `./gradlew test --console=plain && bash -n scripts/terraform-pr-review.sh && bash -n scripts/ci-evidence.sh`
Expected: `BUILD SUCCESSFUL`, no syntax errors.

---

### Task 6: Live validation against real GitHub pull requests

**Files:** none beyond what's already committed; this task pushes branches and opens real PRs against `haftomalemayehu/IAC-Agent` on GitHub, using the already-authenticated `gh` CLI (`repo` scope confirmed available).

**Interfaces:** none — this is operational validation, not code.

This task has real, visible side effects on the user's actual GitHub repository (new branches, PRs, workflow runs, PR comments). Before running it, tell the user explicitly what is about to happen (branch names, that PRs will be opened against `main`, that they'll be left open — or closed per the user's preference — for inspection) so they have a chance to redirect, consistent with the "transparently communicate and confirm before proceeding" rule for actions with external footprint. Do not ask a blocking clarifying question if the user's original task already made the intent unambiguous (it did: it explicitly lists PR URL / run ID / comment ID / duplicate count as required final evidence) — a one-line heads-up before executing is sufficient here, not a stop-and-wait question.

- [ ] **Step 1: Push the hardened branch**

```bash
git push -u origin phase-1c-evidence
```
Expected: push succeeds; note the branch is 0 behind / N ahead of `origin/main`.

- [ ] **Step 2: Open the base hardening PR (Phase 1E code) against `main`**

```bash
gh pr create --base main --head phase-1c-evidence \
  --title "Phase 1E: harden PR review pipeline for real GitHub PRs" \
  --body "Hardens the Terraform PR review workflow: least-privilege permissions, fork-PR guard, resilient BLOCKED rendering, stale plan-hash invalidation, clearer markdown."
```
Record: PR URL, PR number.

- [ ] **Step 3: Watch the triggered workflow run to completion**

```bash
gh pr checks <PR_NUMBER> --watch
gh run list --branch phase-1c-evidence --limit 1
```
Record: workflow run ID, run URL, conclusion.

- [ ] **Step 4: Capture the first review comment (create path)**

```bash
gh api repos/haftomalemayehu/IAC-Agent/issues/<PR_NUMBER>/comments --jq '[.[] | select(.body | contains("<!-- terraform-review -->"))]'
```
Record: comment ID, comment body, count of matching comments (expect exactly 1). This PR's own diff (workflow + script changes only, no `tests/fixtures/valid-vpc` change) should render **ELIGIBLE** — capture this as the ELIGIBLE decision example.

- [ ] **Step 5: Push a second, plan-changing commit to the same PR to prove update-in-place + stale-hash invalidation**

Make a small, benign, additive change to `tests/fixtures/valid-vpc/main.tf` (e.g. add a new non-critical resource or a tag) that changes the plan without introducing replace/destroy/IAM/network/security-group/db/kms resources, so it stays ELIGIBLE but with a **different plan hash**:

```bash
git add tests/fixtures/valid-vpc/main.tf
git commit -m "Phase 1E validation: benign plan change to exercise comment update path"
git push
gh pr checks <PR_NUMBER> --watch
```
Then re-run the comment query from Step 4. Record: same comment ID as before (proves update-in-place, not a new comment), comment count still exactly 1 (duplicate count = 0), new plan hash, and confirm the updated body's `### Evidence` plan hash differs from the first capture and the CI run link points at the new run ID.

Note: since this second run posts the *same* comment id, its rendered body reflects the *new* review being pushed on top of the immediately-preceding one — this is what proves "stale plan hashes invalidate the prior review" in the running system (the workflow only ever shows the latest plan hash as current; anyone who saved/screenshotted the earlier comment is now looking at a hash that no longer matches — call this out explicitly in the final evidence write-up using the two captured plan hashes).

- [ ] **Step 6: Open a second PR for the APPROVAL_REQUIRED example**

The repo already ships a purpose-built fixture for this: `tests/fixtures/replacement-plan/` has a committed `terraform.tfstate` whose `aws_instance.web` has `ami = ami-0c02fb55956c7d316`, while `main.tf` declares `ami = ami-0dd9b1d8f2d606b4a` — a `terraform plan` against that state forces a replace. Rather than hand-editing `valid-vpc` (which has no committed state, so it can only ever show all-`create`), point the workflow's `-chdir` target at this fixture for this demo branch only — GitHub runs the `pull_request`-triggered workflow using the version of the workflow file in the PR's branch, so this is a legitimate way to exercise the real pipeline end-to-end against a real PR.

```bash
git checkout main
git pull
git checkout -b phase-1e-approval-required-demo
sed -i '' 's#tests/fixtures/valid-vpc#tests/fixtures/replacement-plan#g' .github/workflows/terraform-pr.yml
git add .github/workflows/terraform-pr.yml
git commit -m "Phase 1E validation: point CI at replacement-plan fixture to demonstrate APPROVAL_REQUIRED"
git push -u origin phase-1e-approval-required-demo
gh pr create --base main --head phase-1e-approval-required-demo \
  --title "Phase 1E validation: APPROVAL_REQUIRED example (do not merge)" \
  --body "Demonstrates APPROVAL_REQUIRED rendering for Phase 1E acceptance evidence. Not intended to merge."
gh pr checks <PR_NUMBER_2> --watch
```
Record: PR URL, run ID, comment ID, and confirm `Decision: APPROVAL_REQUIRED` in the body with a populated `### Critical changes` and `### Approval reasons`. This branch's only diff from `main` is the fixture path in the workflow, so it is self-evidently a demo, not real infra intent — call this out in the PR body and in the final evidence.

- [ ] **Step 7: Open a third PR for the BLOCKED example**

Use `tests/fixtures/invalid-attribute/` (already defines `aws_vpc.broken` with a nonexistent `definitely_not_valid` attribute, guaranteed to fail `terraform validate`) the same way:

```bash
git checkout main
git checkout -b phase-1e-blocked-demo
sed -i '' 's#tests/fixtures/valid-vpc#tests/fixtures/invalid-attribute#g' .github/workflows/terraform-pr.yml
git add .github/workflows/terraform-pr.yml
git commit -m "Phase 1E validation: point CI at invalid-attribute fixture to demonstrate BLOCKED"
git push -u origin phase-1e-blocked-demo
gh pr create --base main --head phase-1e-blocked-demo \
  --title "Phase 1E validation: BLOCKED example (do not merge)" \
  --body "Demonstrates BLOCKED rendering for Phase 1E acceptance evidence. Not intended to merge."
gh pr checks <PR_NUMBER_3> --watch
```
Record: PR URL, run ID, comment ID, and confirm `Decision: BLOCKED` in the body, and confirm the workflow run still completed (didn't hang or leave the PR without a comment) because of Task 3's `continue-on-error`/`if: always()` changes — this is the concrete proof that BLOCKED renders correctly rather than just failing silently with no comment. Note `tests/fixtures/invalid-attribute` has no `.terraform.lock.hcl`-independent state file and no TFLint/Checkov-relevant content beyond the bad attribute, so `validate` is expected to FAIL while `lint`/`security` stages may legitimately report PASS or NOT_RUN on empty findings — the decision must come out BLOCKED purely from the `validate` FAIL per `ReviewDecisionEngine`/`render_pr_review.py`'s logic ordering.

- [ ] **Step 8: Check permissions actually used**

```bash
gh api repos/haftomalemayehu/IAC-Agent/actions/runs/<RUN_ID>/jobs --jq '.jobs[0].name'
```
And directly cite the `permissions:` block added in Task 3 Step 1 (`contents: read`, `pull-requests: write`) as the permissions-used evidence — GitHub doesn't expose "permissions actually granted to the token" via API, so the committed YAML block plus the fact that only a `pull-requests write` (comment create/update) and `contents read` (checkout) operation occurred in the run logs is the evidence.

- [ ] **Step 9: Decide on cleanup with the user**

Ask (or, if the user already indicated a preference earlier in the conversation, follow it) whether to: (a) leave all three PRs open for their own inspection, (b) close the two pure-demo PRs (`phase-1e-approval-required-demo`, `phase-1e-blocked-demo`) after evidence capture since they intentionally contain a forced replacement / an invalid config and aren't meant to merge, while leaving the main Phase 1E hardening PR open for real review/merge. Do not merge anything to `main` without the user explicitly asking — this task stops at acceptance evidence.

---

## Final Evidence Assembly

After Task 6, compile the required evidence list directly from what was captured (not re-derived or guessed):

- PR URL(s) — hardening PR + two demo PRs
- Workflow run ID(s) for each
- Comment ID(s) — same ID across first/second push on the hardening PR
- First comment creation result (Step 4 raw API response excerpt)
- Second-push update result (Step 5 raw API response excerpt, same ID)
- Duplicate comment count = 0 (the `--jq` count from Steps 4/5)
- Current plan hash (post-Step 5 value)
- Stale-hash invalidation proof (Step 5's before/after plan hashes + the rendered "supersedes" note if the demo happened to trigger it, otherwise the Task 4 offline proof plus a note that the live run's decision didn't change hash-to-hash in a way that needed the notice — be precise about which one actually fired)
- Decision examples: ELIGIBLE (hardening PR, Step 4), APPROVAL_REQUIRED (Step 6), BLOCKED (Step 7) — quote each `Decision:` line and surrounding section
- GitHub permissions used (Task 3 Step 1 YAML block, quoted)
- Java tests PASS (Task 1 Step 6 full-suite output)
- Existing Phase 1C/1D validation remains PASS (same full-suite run plus, if meaningful, a rerun of `scripts/ci-evidence.sh` / `make verify` fmt/validate/plan targets against the untouched fixtures)

Present this as the final message to the user — do not create additional artifacts, dashboards, or documents beyond what's asked.
