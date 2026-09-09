# IAC-Agent

# Terraform Infrastructure-as-Code Engineering Agent

This repository implements a deterministic Terraform IaC control system: a repository-aware orchestration layer that validates, reviews, and gates infrastructure changes before deployment. The goal is not to prompt an LLM to "write Terraform" without verification, but to enforce a production-grade engineering workflow.

## Architecture

```text
User / Engineer
    │
    ▼
Terraform Agent
    │
    ├── Repository discovery
    ├── Provider schema verification
    ├── Terraform authoring and editing
    ├── fmt / validate / lint / security / test / plan
    ├── plan analysis and risk scoring
    ├── approval gate
    └── deployment orchestration (disabled by default)
```

## Core principles

- Provider schemas, Terraform CLI output, policy checks, tests, and human approval are authoritative.
- LLM reasoning is advisory.
- Production apply is disabled by default.
- Terraform state, credentials, and secrets are never committed or logged.
- Drift, cost, security, and replacement risk are reviewed before deployment.

## Repository layout

```text
.
├── agent/
│   ├── CONTRACT.md
│   ├── POLICY.md
│   ├── WORKFLOW.md
│   └── TOOLS.md
├── .agent/
│   ├── config.yaml
│   ├── cache/
│   ├── artifacts/
│   ├── reports/
│   └── sessions/
├── schemas/
├── scripts/
├── policies/
├── tests/
├── terraform/
│   ├── modules/
│   └── environments/
├── src/
│   └── main/java/com/iacagent/iacagent
├── CLAUDE.md
├── Makefile
├── README.md
├── build.gradle
└── .gitignore
```

## Local workflow

```bash
make verify
```

This executes the non-destructive validation pipeline described in the design. The repository pins Terraform and related tools in `.tool-versions` so the same versions are used across local execution and CI.

## Toolchain pinning

The repository includes `.tool-versions` with explicit versions for:

- Terraform 1.6.6
- TFLint 0.52.0
- Checkov 2.3.365
- Infracost 0.10.39

This prevents silent drift from a newer toolchain changing the control plane behavior.

## Threat model and trust boundaries

The agent only authorizes code changes inside the repository. It does not mutate live infrastructure by default and it blocks destructive or state-changing actions without explicit approval.

Trust boundaries:

- repository and Git policy
- provider schema and Terraform CLI
- security and policy tools
- approved human reviewer
- cloud API read-only inspection

## Approval model

The agent requires explicit human approval for:

- production apply
- destroy or replacement operations
- state operations
- IAM privilege expansion
- network exposure
- database changes
- KMS changes
- large cost increases

## Validation semantics

Every check must resolve to one of:

- PASS
- FAIL
- BLOCKED
- NOT RUN

The system does not infer success from a missing tool or a nonzero assumption.

## Example Terraform

The repository includes a minimal example module under `terraform/modules/network` and an environment under `terraform/environments/dev`. These are intentionally small, cost-conscious, and suitable for validation/testing.

## Java control layer

The Spring Boot service in `src/main/java/com/iacagent/iacagent` models the execution loop used by the engineering control system:

- plan generation
- validation
- approval gating
- execution state

This keeps the control-plane logic in code while the repository documents and scripts implement the real Terraform workflow.

## Recommended next steps

1. install Terraform, TFLint, Checkov, and Infracost in CI/local toolchain;
2. run `make verify` in a repo with Terraform providers initialized;
3. add remote plan review and protected-branch PR automation;
4. connect the control plane to a GitHub or GitLab policy workflow.
