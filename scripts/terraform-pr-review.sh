#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -z "${GITHUB_REPOSITORY:-}" ]]; then
  echo "GITHUB_REPOSITORY is required"
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI is required"
  exit 1
fi

ARTIFACT_DIR=".agent/sessions/ci-evidence"
PLAN_PATH=".agent/artifacts/tfplan"
MARKER='<!-- terraform-review -->'

if [[ -f "$PLAN_PATH" ]]; then
  PLAN_HASH="$(sha256sum "$PLAN_PATH" | awk '{print $1}')"
else
  # A failed `terraform plan` (e.g. validate/lint/security failures upstream)
  # leaves no plan artifact. The review must still be posted as BLOCKED, so
  # hash whatever evidence exists instead of aborting the whole pipeline.
  echo "terraform tfplan artifact missing; hashing available evidence for a BLOCKED review"
  PLAN_HASH="$(find "$ARTIFACT_DIR" -type f -exec sha256sum {} \; 2>/dev/null | sha256sum | awk '{print $1}')"
fi
PLAN_HASH_PREFIX="sha256:${PLAN_HASH}"
echo "$PLAN_HASH_PREFIX" > .agent/artifacts/tfplan.sha256

HASH_VALUE="$(cat .agent/artifacts/tfplan.sha256)"

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
  echo "FAIL: could not list existing PR comments (permissions or API error):"
  cat /tmp/comments_err.log
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
echo "$BODY" > .agent/sessions/ci-evidence/pr-review.md

if [[ -n "$EXISTING_ID" ]]; then
  if ! gh api --method PATCH "repos/${GITHUB_REPOSITORY}/issues/comments/${EXISTING_ID}" -f body="$BODY" >/dev/null; then
    echo "FAIL: could not update existing review comment ${EXISTING_ID}"
    exit 1
  fi
else
  if ! gh api --method POST "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" -f body="$BODY" >/dev/null; then
    echo "FAIL: could not create review comment"
    exit 1
  fi
fi
