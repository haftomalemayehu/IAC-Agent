# Workflow

## Phase 1

- repository inspection
- provider schema verification
- Terraform authoring
- formatting
- validation
- linting
- security scanning
- testing
- planning
- plan review
- approval gate

## Phase 2

- Infracost analysis
- OPA / Conftest policy checks
- GitHub/GitLab PR automation
- Terraform MCP integration
- cloud read-only drift detection

## Phase 3

- HCP Terraform or enterprise remote orchestration
- Vault/secret manager integration
- multi-cloud support
- audit records and central policy libraries

## Required sequence

```text
REQUEST -> DISCOVER -> DESIGN -> VERIFY_SCHEMA -> AUTHOR -> FORMAT -> VALIDATE -> LINT -> SECURITY_SCAN -> TEST -> PLAN -> PLAN_ANALYSIS -> COST_ANALYSIS -> RISK_REVIEW -> READY_FOR_REVIEW -> APPROVAL -> APPLY -> VERIFY -> COMPLETE
```
