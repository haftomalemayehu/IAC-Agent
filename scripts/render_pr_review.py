#!/usr/bin/env python3
"""Render the Terraform PR review comment body from CI evidence.

Pure function of the evidence directory + optional prior-review context.
No network calls - safe to run locally against synthetic evidence for
manual/automated verification before wiring into a real PR.
"""
import argparse
import json
import pathlib
from typing import Optional


MARKER = "<!-- terraform-review -->"


def load_json(path: pathlib.Path, default):
    return json.loads(path.read_text()) if path.exists() else default


def stage_status(result: dict, stage: str) -> str:
    return result.get("stages", {}).get(stage, "NOT_RUN")


def render(evidence_dir: pathlib.Path, plan_hash: str, ci_run_url: Optional[str], prior_plan_hash: Optional[str]) -> str:
    result = load_json(evidence_dir / "result.json", {})
    plan = load_json(evidence_dir / "plan-summary.json", {"create": 0, "update": 0, "replace": 0, "destroy": 0})

    schema = stage_status(result, "providerSchema")
    validate = stage_status(result, "validate")
    security = stage_status(result, "security")
    risk = result.get("risk", "LOW")

    critical = []
    if plan.get("replace", 0) > 0:
        critical.append("resources will be replaced")
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
